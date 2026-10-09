#!/usr/bin/env python3
"""Stage HTTPS 204, domestic TCP, overseas pages/trace and a quick download."""
import argparse
import concurrent.futures as futures
import copy
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import statistics
import subprocess
import threading
import time

import yaml
import select_nodes as s
from mobile_pilot import check_site, check_sites, SITES, PAGE_SITES, CONNECTIVITY_SITES, POST_SITES, SITE_WORKERS, UDP_TYPES

XXAPI = 'https://v2.xxapi.cn/api/tcping'
LABELS = {'passed': '通', 'failed': '不通', 'unknown': '未验证',
          'unstable': '波动', 'needs_review': '需人工复核', 'skipped': '未测'}


class Pace:
    def __init__(self, interval=.2):
        self.interval = interval
        self.lock = threading.Lock()
        self.next_at = 0
        self.blocked = False

    def wait(self):
        with self.lock:
            if self.blocked:
                return False
            delay = self.next_at - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self.next_at = time.monotonic() + self.interval
            return True


def endpoint_key(node):
    return node['server'], int(node['port'])


def tcp_supported(node):
    return node['type'] not in UDP_TYPES and node.get('network') != 'quic'


def mobile_control_paths(value, path=()):
    """Reject decoded controls: mobile YAML writers may emit them literally."""
    if isinstance(value, str):
        if any((ord(c) < 32 and c not in '\t\n\r') or 127 <= ord(c) <= 159
               or 0xd800 <= ord(c) <= 0xdfff or ord(c) in (0xfffe, 0xffff) for c in value):
            return ['.'.join(path) or '<root>']
        return []
    if isinstance(value, dict):
        result = []
        for key, item in value.items():
            result.extend(mobile_control_paths(key, path + ('<key>',)))
            result.extend(mobile_control_paths(item, path + (str(key),)))
        return result
    if isinstance(value, list):
        return [p for i, item in enumerate(value) for p in mobile_control_paths(item, path + (str(i),))]
    return []


def filter_mobile_nodes(nodes):
    safe, rejected = [], {}
    for node in nodes:
        paths = mobile_control_paths(node)
        if paths:
            rejected[node['name']] = paths
        else:
            safe.append(node)
    return safe, rejected


def parse_xxapi(data, host, port):
    if not isinstance(data, dict):
        return {'status': 'unknown', 'reason': '接口返回格式异常'}
    if data.get('code') == -2 and data.get('msg') == '连接失败':
        return {'status': 'failed', 'reason': '该服务探测点 TCP 连接失败'}
    info = data.get('data')
    if data.get('code') != 200 or not isinstance(info, dict):
        return {'status': 'unknown', 'reason': '接口错误，不作为节点不通'}
    match = re.fullmatch(r'(\d+(?:\.\d+)?)ms', str(info.get('ping', '')))
    try:
        valid = (info.get('address', '').lower().rstrip('.') == host.lower().rstrip('.')
                 and type(info.get('port')) in (str, int)
                 and int(info.get('port')) == port and match is not None)
    except (ValueError, TypeError, AttributeError):
        valid = False
    if not valid or not math.isfinite(float(match[1])):
        return {'status': 'unknown', 'reason': '返回目标、端口或延迟不匹配'}
    return {'status': 'passed', 'latency_ms': float(match[1]),
            'reason': '该服务探测点单次 TCP 连接成功'}


def probe_xxapi(key, pace):
    host, port = key
    outcome = {'provider': 'xxapi', 'probe_network': '服务未公开探测点运营商，不能标记为移动线路',
               'attempts': 1, 'checked_at': s.datetime.now(s.TZ).isoformat(timespec='seconds')}
    try:
        try:
            if not ipaddress.ip_address(host).is_global:
                return {**outcome, 'status': 'unknown', 'attempts': 0, 'reason': '非公网入口不提交第三方'}
        except ValueError:
            pass
        if not pace.wait():
            return {**outcome, 'status': 'unknown', 'attempts': 0, 'reason': '服务限流，未提交检测'}
        with s.session() as client:
            response = client.get(XXAPI, params={'address': host, 'port': port}, timeout=(5, 10))
            if response.status_code == 429:
                pace.blocked = True
                return {**outcome, 'status': 'unknown', 'reason': '接口限流'}
            response.raise_for_status()
            data = response.json()
            return {**outcome, **parse_xxapi(data, host, port), 'request_id': data.get('request_id') if isinstance(data, dict) else None}
    except (s.requests.RequestException, ValueError):
        return {**outcome, 'status': 'unknown', 'reason': '接口连接、超时或响应异常'}


def service_status():
    """Inspect availability without submitting probes or solving security challenges."""
    services = {'xxapi': {'mode': 'automatic', 'url': 'https://xxapi.cn/doc/tcping',
                          'status': 'enabled', 'request_rate_per_second': 5},
                'itdog': {'mode': 'manual_comparison', 'url': 'https://www.itdog.cn/batch_tcping/'},
                'tcping_cn': {'mode': 'manual_comparison', 'url': 'https://www.tcping.cn/tcping'}}
    try:
        with s.session() as client:
            result = client.get('https://www.tcping.cn/api/probe/options', timeout=10)
            result.raise_for_status()
            options = result.json()
            services['tcping_cn'].update(status='manual_required',
                reason='自动接口要求人机验证' if options.get('captcha') else '网页服务可用，尚无已验证的全量自动接口')
    except (s.requests.RequestException, ValueError):
        services['tcping_cn'].update(status='unavailable', reason='服务状态查询失败')
    try:
        with s.session() as client:
            result = client.get(services['itdog']['url'], timeout=10)
            challenged = result.status_code in (403, 429) or any(word in result.text.lower() for word in ('cf-chl-', 'just a moment'))
            services['itdog'].update(status='manual_required', reason='网页安全验证' if challenged else '网页批量服务；未提供已验证的公开自动接口')
    except s.requests.RequestException:
        services['itdog'].update(status='unavailable', reason='服务状态查询失败')
    return services


def classify_all(nodes, workers=10, probe=probe_xxapi, pace=None, on_record=None):
    pace = pace or Pace()
    endpoints = sorted({endpoint_key(n) for n in nodes if tcp_supported(n)})
    measured = {}
    records, by_endpoint = [], {}
    for node in nodes:
        record = {'id': node['name'], 'server': node['server'], 'port': node['port'],
                  'protocol': node['type'], 'entry': {'status': 'unknown',
                  'reason': 'UDP 协议不适用 TCP 入口判定', 'attempts': 0}, 'websites': None, 'exit': None}
        records.append(record)
        if tcp_supported(node):
            by_endpoint.setdefault(endpoint_key(node), []).append(record)
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        jobs = {pool.submit(probe, key, pace): key for key in endpoints}
        for job in futures.as_completed(jobs):
            key = jobs[job]
            measured[key] = job.result()
            for record in by_endpoint[key]:
                record['entry'] = copy.deepcopy(measured[key])
                if on_record:
                    on_record(record)
            if len(measured) % 100 == 0 or len(measured) == len(endpoints):
                counts = {v: sum(r['status'] == v for r in measured.values()) for v in ('passed', 'failed', 'unknown')}
                print(f'TCP 入口 {len(measured)}/{len(endpoints)}：{counts}', flush=True)
    return records, len(endpoints)


def shard_nodes(nodes, index, count):
    if count < 1 or not 0 <= index < count:
        raise ValueError('分片编号或数量无效')
    # All credentials sharing a host/port stay together: only one TCP request.
    return [node for node in nodes if int(hashlib.sha256(
        json.dumps(endpoint_key(node), ensure_ascii=False).encode()).hexdigest(), 16) % count == index]


DOWNLOAD_URL = 'https://speed.cloudflare.com/__down?bytes=1000000'
DOWNLOAD_BYTES = 1_000_000
DOWNLOAD_BUDGET = 6


def precheck_204(port):
    outcomes = [{'Google204': check_site(port, 'Google204', SITES['Google204'], timeout=(2, 3))}
                for _ in range(3)]
    return summarize_rounds(outcomes, labels=('Google204',))['Google204']


def quick_download(port):
    """One bounded 1 MB sample; conservative speed includes TLS and first byte."""
    started = time.perf_counter()
    received = 0
    result = {'status': 'failed', 'url': DOWNLOAD_URL, 'requested_bytes': DOWNLOAD_BYTES,
              'budget_seconds': DOWNLOAD_BUDGET, 'speed_mib_s': None}
    with s.session() as client:
        client.proxies = {'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}
        try:
            with client.get(DOWNLOAD_URL, stream=True, timeout=(2, 1), allow_redirects=False,
                            headers={'Accept-Encoding': 'identity', 'Cache-Control': 'no-cache'}) as response:
                if (response.status_code != 200 or response.url != DOWNLOAD_URL
                        or response.headers.get('Content-Length') != str(DOWNLOAD_BYTES)
                        or response.headers.get('Content-Type', '').split(';')[0] != 'application/octet-stream'
                        or response.headers.get('Content-Encoding', 'identity') != 'identity'):
                    return {**result, 'reason': '下载状态、文件长度或类型不匹配'}
                # read1 returns available data without waiting to fill a large chunk.
                while received <= DOWNLOAD_BYTES and time.perf_counter() - started < DOWNLOAD_BUDGET:
                    chunk = response.raw.read1(16384)
                    if not chunk:
                        break
                    received += len(chunk)
                elapsed = time.perf_counter() - started
                if received != DOWNLOAD_BYTES or elapsed > DOWNLOAD_BUDGET:
                    return {**result, 'reason': '未在时间预算内完整下载 1 MB', 'received_bytes': received,
                            'elapsed_ms': round(elapsed * 1000, 1)}
                return {**result, 'status': 'passed', 'reason': '1 MB 快速采样完整下载；包含建连耗时，不代表峰值带宽',
                        'received_bytes': received, 'elapsed_ms': round(elapsed * 1000, 1),
                        'speed_mib_s': round(received / elapsed / 1048576, 3)}
        except (s.requests.RequestException, OSError, s.requests.packages.urllib3.exceptions.HTTPError):
            return {**result, 'reason': '快速下载连接、TLS 或读取失败', 'received_bytes': received}


def probe_pipeline(nodes, binary, root, probe=probe_xxapi, precheck=precheck_204,
                   site_check=None, download=quick_download, interval=.25, workers=16):
    """Per-node stages are ordered, while different nodes overlap across stages."""
    if not nodes:
        return [], 0
    site_check = site_check or (lambda port: check_sites(port, POST_SITES))
    listeners, ports = s.make_listeners({'id': n['name']} for n in nodes)
    pace, lock, tcp_jobs = Pace(interval), threading.Lock(), {}
    progress = {'done': 0, 'precheck': 0, 'tcp': 0, 'websites': 0, 'download': 0}
    with s.Core(binary, root, nodes, listeners), futures.ThreadPoolExecutor(max_workers=10) as tcp_pool:
        def measure(node):
            port = ports[node['name']]
            record = {'id': node['name'], 'server': node['server'], 'port': node['port'], 'protocol': node['type'],
                      'entry': {'status': 'unknown', 'attempts': 0, 'reason': '204 未通过，未提交国内 TCP 检测'},
                      'websites': None, 'exit': None, 'download': {'status': 'skipped', 'reason': '未进入下载阶段'}}
            record['precheck'] = precheck(port)
            if record['precheck']['status'] == 'passed':
                if not tcp_supported(node):
                    record['entry']['reason'] = 'UDP 协议不适用 TCP 检测，后续阶段未测'
                else:
                    key = endpoint_key(node)
                    with lock:
                        if key not in tcp_jobs:
                            tcp_jobs[key] = tcp_pool.submit(probe, key, pace)
                        job = tcp_jobs[key]
                    record['entry'] = copy.deepcopy(job.result())
                if record['entry']['status'] == 'passed':
                    record['websites'] = summarize_rounds([site_check(port)], labels=POST_SITES)
                    traces = [record['websites'][label]['attempts'][0] for label in ('ChatGPTTrace', 'ClaudeTrace')
                              if record['websites'][label]['status'] == 'passed'
                              and record['websites'][label]['attempts'][0].get('exit_ip')]
                    if traces:
                        record['exit'] = {'id': record['id'], 'exit_ip': traces[0]['exit_ip'],
                                          'country_code': traces[0]['country_code'], 'source': 'verified_trace'}
                        record['exit_consistent'] = len({(r['exit_ip'], r['country_code']) for r in traces}) == 1
                    else:
                        try:
                            record['exit'] = s.query_exit(port, {'id': record['id']})
                        except (s.requests.RequestException, ValueError, KeyError):
                            record['exit_reason'] = '出口 IP/地区未确认'
                    if any(v['status'] == 'passed' for v in record['websites'].values()):
                        record['download'] = download(port)
                    else:
                        record['download']['reason'] = '海外网页与 trace 均未通过，跳过下载'
            with lock:
                progress['done'] += 1
                progress['precheck'] += record['precheck']['status'] == 'passed'
                progress['tcp'] += record['entry']['status'] == 'passed'
                progress['websites'] += record['websites'] is not None
                progress['download'] += record['download']['status'] == 'passed'
                if progress['done'] % 100 == 0 or progress['done'] == len(nodes):
                    print(f'分阶段流水线 {progress["done"]}/{len(nodes)}：204通过 {progress["precheck"]}，TCP通过 {progress["tcp"]}，网站完成 {progress["websites"]}，快速下载通过 {progress["download"]}', flush=True)
            return record
        with futures.ThreadPoolExecutor(max_workers=workers) as pool:
            records = list(pool.map(measure, nodes))
    return records, len(tcp_jobs)


def merge_shards(bundle, parts, count):
    if len(parts) != count or {p['index'] for p in parts} != set(range(count)):
        raise ValueError('缺少分片，拒绝发布')
    combined = {}
    for part in parts:
        if part.get('bundle_id') != bundle['id']:
            raise ValueError('分片来源批次不一致，拒绝发布')
        if part['count'] != count:
            raise ValueError('分片数量不一致')
        subset = shard_nodes(bundle['nodes'], part['index'], count)
        expected = {n['name'] for n in subset}
        rows = part['records']
        if len(rows) != len(expected) or {r['id'] for r in rows} != expected:
            raise ValueError('分片存在漏测、重复或串片节点')
        by_id = {r['id']: r for r in rows}
        eligible = {endpoint_key(n) for n in subset if tcp_supported(n) and
                    by_id[n['name']].get('precheck', {}).get('status') == 'passed'}
        if part['endpoint_count'] != len(eligible):
            raise ValueError('TCP 入口统计不完整')
        for record in rows:
            pre = record.get('precheck', {})
            if pre.get('round_count') != 3 or len(pre.get('attempts', [])) != 3:
                raise ValueError('节点缺少三轮 204 检测')
            passed = sum(a.get('status') == 'passed' for a in pre['attempts'])
            if pre.get('passed_count') != passed or (pre.get('status') == 'passed') != (passed == 3):
                raise ValueError('204 汇总与三轮结果不一致')
            if record['entry']['status'] != 'unknown' and pre['status'] != 'passed':
                raise ValueError('204 未通过却进入 TCP 阶段')
            if pre['status'] != 'passed' and (record['entry'].get('attempts') != 0 or record.get('websites')):
                raise ValueError('204 未通过却执行后续阶段')
            if record['entry']['status'] == 'passed' and (not record.get('websites') or any(
                    record['websites'].get(site, {}).get('round_count') != 1 or
                    len(record['websites'].get(site, {}).get('attempts', [])) != 1 for site in POST_SITES)):
                raise ValueError('通过节点缺少完整网站单轮检测')
            if record['entry']['status'] == 'passed' and pre['status'] != 'passed':
                raise ValueError('节点未按阶段筛选')
            should_download = record['entry']['status'] == 'passed' and any(
                v['status'] == 'passed' for v in (record.get('websites') or {}).values())
            if record.get('download', {}).get('status') not in (('passed', 'failed') if should_download else ('skipped',)):
                raise ValueError('下载阶段漏测或顺序异常')
            if record.get('download', {}).get('status') == 'passed' and (
                    record['entry']['status'] != 'passed' or
                    not any(v['status'] == 'passed' for v in (record.get('websites') or {}).values()) or
                    record['download'].get('received_bytes') != DOWNLOAD_BYTES or
                    not 0 < record['download'].get('elapsed_ms', math.inf) <= DOWNLOAD_BUDGET * 1000):
                raise ValueError('下载结果不完整或节点未通过前置阶段')
            combined[record['id']] = record
    return [combined[n['name']] for n in bundle['nodes']], sum(p['endpoint_count'] for p in parts)


def summarize_rounds(rounds, labels=SITES):
    summarized = {}
    for label in labels:
        attempts = [row[label] for row in rounds]
        passed = sum(a['status'] == 'passed' for a in attempts)
        status = ('passed' if passed == len(rounds) else 'needs_review' if any(a['status'] == 'needs_review' for a in attempts)
                  else 'unstable' if passed else 'failed')
        delays = [a['elapsed_ms'] for a in attempts if a.get('elapsed_ms') is not None and a['status'] == 'passed']
        summarized[label] = {'status': status, 'passed_count': passed, 'round_count': len(rounds),
                              'median_elapsed_ms': round(statistics.median(delays), 1) if delays else None,
                              'max_elapsed_ms': max(delays) if delays else None,
                              'attempts': attempts}
    return summarized



def website_count(record):
    results = record.get('websites') or {}
    return sum(results.get(label, {}).get('status') == 'passed' for label in PAGE_SITES)


def connectivity_count(record):
    results = record.get('websites') or {}
    return int((record.get('precheck') or results.get('Google204', {})).get('status') == 'passed') + sum(
        results.get(label, {}).get('status') == 'passed' for label in ('ChatGPTTrace', 'ClaudeTrace'))


def rank_key(record):
    pre = record.get('precheck') or {}
    downloaded = record.get('download') or {}
    return (downloaded.get('status') != 'passed', -website_count(record), -connectivity_count(record),
            pre.get('median_elapsed_ms') if pre.get('median_elapsed_ms') is not None else math.inf,
            -(downloaded.get('speed_mib_s') or 0), record['entry'].get('latency_ms', math.inf), record['id'])


def render_comparison(base, records, mapping):
    """Keep all parseable samples for the user's local positive/negative comparison."""
    config = {key: copy.deepcopy(base[key]) for key in (
        'mixed-port', 'allow-lan', 'mode', 'log-level', 'external-controller', 'dns', 'rules', 'rule-providers') if key in base}
    config.setdefault('dns', {})
    references = {rule.split(',')[1] for rule in config.get('rules', []) if rule.startswith('RULE-SET,')}
    config['rule-providers'] = {k: v for k, v in config.get('rule-providers', {}).items() if k in references}
    proxies, classified, regions = [], {v: [] for v in ('passed', 'failed', 'unknown')}, {}
    ranked = sorted(records, key=rank_key)
    non_dc, seen_ips = [], set()
    for record in ranked:
        region_code = (record.get('exit') or {}).get('country_code')
        region = s.COUNTRIES.get(region_code, region_code) if region_code else '地区未确认'
        status = record['entry']['status']
        pre = record.get('precheck') or {}
        parts = [region]
        if (record.get('download') or {}).get('status') == 'passed':
            parts.append(f"{record['download']['speed_mib_s']:.2f}MiB/s")
        if pre.get('status') == 'passed':
            parts.append(f"204 {pre['median_elapsed_ms']}ms" if pre.get('median_elapsed_ms') is not None else '204通过')
        elif pre:
            parts.append('204未通过')
        if record.get('websites'):
            # Show the measured denominator when repairing older publications.
            tested = sum(label in record['websites'] for label in PAGE_SITES)
            parts.append(f'网页{website_count(record)}/{tested}')
        parts += [f'TCP{LABELS[status]}', record['id'][2:]]
        name = ' | '.join(parts)
        record['name'] = name
        node = copy.deepcopy(mapping[record['id']]); node['name'] = name; proxies.append(node)
        classified[status].append(name)
        eligible = status == 'passed' and (record.get('download') or {}).get('status') == 'passed'
        if region_code and eligible:
            regions.setdefault(region, []).append(name)
        ip = (record.get('exit') or {}).get('exit_ip')
        if (eligible and record.get('exit_consistent') is not False and record.get('ip_type', {}).get('hosting') is False
                and record['ip_type'].get('status') == 'success' and ip and ip not in seen_ips and len(non_dc) < 30):
            non_dc.append(name); seen_ips.add(ip)
    fast = [r['name'] for r in ranked if (r.get('download') or {}).get('status') == 'passed']
    recommended = fast or classified['passed'] or classified['unknown'] or classified['failed']
    def group(name, names):
        return {'name': name, 'type': 'select', 'proxies': names or ['REJECT']}
    # One regional picker keeps each region's 30-node quota without 20+ tabs.
    regional = [node for region in sorted(regions) for node in regions[region][:30]]
    config['proxies'] = proxies
    config['proxy-groups'] = [
        group('🚀 全局选择', ['⭐ 综合优选', '🏠 非机房 IP', '🌍 按地区选择',
                            '📶 TCP通', '⛔ TCP不通', '🔎 TCP未验证', '🎯 全部节点', 'DIRECT']),
        group('⭐ 综合优选', recommended), group('🏠 非机房 IP', non_dc),
        group('🌍 按地区选择', regional),
        group('📶 TCP通', classified['passed']), group('⛔ TCP不通', classified['failed']),
        group('🔎 TCP未验证', classified['unknown']), group('🎯 全部节点', [n['name'] for n in proxies]),
    ]
    if mobile_control_paths(config):
        raise ValueError('配置包含解码后的控制字符，拒绝发布到手机')
    return config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--phase', choices=('all', 'prepare', 'probe', 'publish', 'repair'), default='all')
    parser.add_argument('--sample', help='Optional fixture; default pulls ALL subscriptions')
    parser.add_argument('--work-dir', default='.node-work/availability')
    parser.add_argument('--shard-index', type=int, default=0)
    parser.add_argument('--shard-count', type=int, default=4)
    parser.add_argument('--results-dir', default='.node-work/shards')
    args = parser.parse_args()
    root = Path(args.work_dir).resolve(); root.mkdir(parents=True, exist_ok=True)
    binary = str(Path(args.mihomo).resolve())
    bundle_path = root / 'bundle.json'
    if args.phase == 'repair':
        previous = json.loads(Path('连通性报告.json').read_text())
        published = yaml.safe_load(Path('优选配置.yaml').read_text())
        by_name = {n['name']: n for n in published['proxies']}
        nodes = [{**by_name[r['name']], 'name': r['id']} for r in previous['nodes']]
        nodes, mobile_rejections = filter_mobile_nodes(nodes)
        retained = {n['name'] for n in nodes}
        records = [r for r in previous['nodes'] if r['id'] in retained]
        if not nodes:
            raise RuntimeError('没有手机可安全读取的节点；保留旧订阅')
        bundle = {'base': yaml.safe_load(Path('聚合配置.yaml').read_text()), 'nodes': nodes,
                  'metadata': {r['id']: {'sources': r.get('sources', [])} for r in records},
                  'sources': previous['sources'], 'input_count': previous['input_unique_count'],
                  'rejected': sorted(set(previous['invalid_node_ids']) | set(mobile_rejections)),
                  'mobile_rejections': {**previous.get('mobile_rejections', {}), **mobile_rejections},
                  'services': previous['services'], 'scope': previous['scope'],
                  'parallel_shards': previous.get('parallel_shards', 1),
                  'measurements_updated_at': previous.get('measurements_updated_at', previous['updated_at'])}
        endpoint_count = previous.get('unique_tcp_endpoints', len({endpoint_key(n) for n in nodes if tcp_supported(n)}))
        print(f'仅修复手机兼容性：剔除 {len(mobile_rejections)} 个损坏节点，保留 {len(nodes)} 个；不重新探测', flush=True)
    elif args.phase in ('all', 'prepare'):
        base = yaml.safe_load(Path('聚合配置.yaml').read_text())
        if args.sample:
            samples = yaml.safe_load(Path(args.sample).read_text())['samples']
            nodes = [{**r['node'], 'name': r['id']} for r in samples]
            metadata, sources = {}, []
        else:
            nodes, metadata, sources = s.collect(base, root, extra_sources=s.load_sources(Path('节点来源.yaml')))
        input_count = len(nodes)
        if not nodes:
            raise RuntimeError('没有来源节点；保留已发布订阅')
        nodes, mobile_rejections = filter_mobile_nodes(nodes)
        if not nodes:
            raise RuntimeError('全部节点未通过手机兼容性检查；保留旧订阅')
        nodes, rejected = s.Core(binary, root, nodes).validate_nodes()
        rejected += list(mobile_rejections)
        bundle = {'base': base, 'nodes': nodes, 'metadata': metadata, 'sources': sources,
                  'input_count': input_count, 'rejected': rejected, 'services': service_status(),
                  'mobile_rejections': mobile_rejections,
                  'scope': 'fixture' if args.sample else 'all_subscriptions',
                  'prepared_at': s.datetime.now(s.TZ).isoformat(timespec='seconds')}
        bundle['id'] = hashlib.sha256(json.dumps(bundle, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        bundle_path.write_text(json.dumps(bundle, ensure_ascii=False))
        print(f'全量节点 {input_count}，内核可解析 {len(nodes)}；已准备分阶段流水线输入，最后进行 1 MB 快速下载', flush=True)
        if args.phase == 'prepare':
            return
    else:
        bundle = json.loads(bundle_path.read_text())
    nodes = bundle['nodes']
    base, metadata, sources = bundle['base'], bundle['metadata'], bundle['sources']
    input_count, rejected, services = bundle['input_count'], bundle['rejected'], bundle['services']
    mapping = {n['name']: n for n in nodes}
    if args.phase == 'probe':
        subset = shard_nodes(nodes, args.shard_index, args.shard_count)
        print(f'分片 {args.shard_index + 1}/{args.shard_count}：{len(subset)} 节点，TCP 与网站同时检测', flush=True)
        records, endpoint_count = probe_pipeline(subset, binary, root, interval=.25 * args.shard_count)
        result = {'bundle_id': bundle['id'], 'index': args.shard_index, 'count': args.shard_count,
                  'records': records, 'endpoint_count': endpoint_count}
        (root / f'shard-{args.shard_index}.json').write_text(json.dumps(result, ensure_ascii=False))
        return
    if args.phase == 'publish':
        parts = [json.loads(p.read_text()) for p in Path(args.results_dir).glob('shard-*.json')]
        records, endpoint_count = merge_shards(bundle, parts, args.shard_count)
    elif args.phase != 'repair':
        records, endpoint_count = probe_pipeline(nodes, binary, root)
    reachable = [r for r in records if r['entry']['status'] == 'passed']
    if args.phase != 'repair':
        ip_types = s.lookup_ip_types(r['exit']['exit_ip'] for r in records if r['exit'])
        for record in records:
            record['sources'] = metadata.get(record['id'], {}).get('sources', [])
            record['ip_type'] = ip_types.get((record.get('exit') or {}).get('exit_ip'), {'status': 'unknown', 'hosting': None})
    config = render_comparison(base, records, mapping)
    candidate = root / 'selected.yaml'; s.dump(candidate, config)
    checked = subprocess.run([binary, '-t', '-d', str(root), '-f', str(candidate)], capture_output=True, text=True, timeout=90)
    if checked.returncode:
        raise RuntimeError('最终订阅校验失败，不发布')
    now = s.datetime.now(s.TZ).isoformat(timespec='seconds')
    counts = {v: sum(r['entry']['status'] == v for r in records) for v in ('passed', 'failed', 'unknown')}
    repairing = args.phase == 'repair'
    report = {'updated_at': now, 'scope': bundle['scope'], 'schema_version': 3,
              'measurements_updated_at': bundle.get('measurements_updated_at', now),
              'publication_mode': 'compatibility_repair' if repairing else 'full',
              'mobile_rejections': bundle.get('mobile_rejections', {}),
              'pipeline': True, 'parallel_shards': bundle.get('parallel_shards', args.shard_count if args.phase == 'publish' else 1),
              'website_workers_per_shard': 16,
              'parallel_sites_per_node': previous.get('parallel_sites_per_node', 3) if repairing else SITE_WORKERS,
              'test_targets': previous.get('test_targets', {k: SITES[k] for k in PAGE_SITES}) if repairing else dict(SITES),
              'stages': previous.get('stages', ['TCP', 'websites']) if repairing else ['HTTPS204', 'domestic_TCP', 'websites_and_trace', 'quick_download'],
              'precheck_rounds': previous.get('precheck_rounds', 0) if repairing else 3,
              'website_rounds': previous.get('website_rounds', 3) if repairing else 1,
              'download_test': previous.get('download_test', False) if repairing else True,
              'download_settings': previous.get('download_settings') if repairing else {'url': DOWNLOAD_URL, 'bytes': DOWNLOAD_BYTES, 'budget_seconds': DOWNLOAD_BUDGET, 'rounds': 1, 'read_timeout_seconds': 1, 'includes_handshake': True},
              'input_unique_count': input_count, 'parseable_count': len(nodes), 'invalid_node_ids': rejected,
              'unique_tcp_endpoints': endpoint_count,
              'total_unique_tcp_endpoints': len({endpoint_key(n) for n in nodes if tcp_supported(n)}),
              'precheck_counts': {v: sum((r.get('precheck') or {}).get('status') == v for r in records)
                                  for v in ('passed', 'failed', 'unstable', 'needs_review')},
              'entry_counts': counts, 'website_tested_count': len(reachable),
              'website_target_count': sum(label in (previous.get('test_targets') or {}) for label in PAGE_SITES) if repairing else len(PAGE_SITES),
              'all_websites_passed': sum(all((r.get('websites') or {}).get(label, {}).get('status') == 'passed' for label in PAGE_SITES) for r in records),
              'three_connectivity_passed': sum(connectivity_count(r) == 3 for r in records),
              'download_counts': {v: sum((r.get('download') or {}).get('status') == v for r in records)
                                  for v in ('passed', 'failed', 'skipped')},
              'services': services, 'sources': sources, 'nodes': records}
    Path('优选配置.yaml').write_text(f'# 分阶段检测；{now}；检测轮数和下载设置见连通性报告\n' + candidate.read_text())
    Path('连通性报告.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    rows = ['# 节点分阶段连通性与快速下载', '', f'发布时间：{now}；检测数据时间：{report["measurements_updated_at"]}', '',
            f'去重节点 {input_count}；内核可解析 {len(nodes)}；TCP 入口总数 {report["total_unique_tcp_endpoints"]}，本轮实际提交 {endpoint_count}。', '',
            f'204 全通过 {report["precheck_counts"]["passed"]}；TCP 通 {counts["passed"]}，不通 {counts["failed"]}，未验证 {counts["unknown"]}；海外访问检测 {len(reachable)}；快速下载通过 {report["download_counts"]["passed"]}。', '',
            f'检测顺序：{" → ".join(report["stages"])}。204 {report["precheck_rounds"]} 轮；网站与 trace 各 {report["website_rounds"]} 轮；下载检测 {"开启" if report["download_test"] else "关闭"}。兼容性修复保留原检测数据，未测项目保持未测。', '',
            '204 三轮均返回 HTTPS 204 且无正文才进入 TCP；204 未通过的节点仍保留在“TCP未验证”与“全部节点”组，名称注明“204未通过”，不伪造国内入口不通。UDP 的 TCP 阶段不适用，保持未验证。', '',
            'TCP 来自小小 API 的国内探测点，运营商未公开，不代表移动或手机本地必然可用。共享主机和端口只提交一次，不同凭据分别检查 204 和海外访问。接口限流、超时、异常和目标不匹配均记为未验证。', '',
            f'本轮 {report["parallel_shards"]} 个并行 Actions 分片，每片最多同时检测 16 个节点。同一节点按顺序过关，不同节点可同时处于不同阶段；海外地址各请求一次，每节点最多五个请求并发；新增网站不会增加并发连接上限。', '',
            '海外网页目标：' + '、'.join(PAGE_SITES) + '；另测 ChatGPT、Claude 两个 trace。', '',
            '网页只读取前 16 KB；403、验证码或风控记为需人工复核。trace 必须返回预期域名、公网出口 IP、地区和 HTTPS 标识，只表示域名连通，不证明登录、对话或视频播放可用。', '',
            'TCP 通且至少一个海外网页或 trace 通过后，使用 Cloudflare 官方 __down?bytes=1000000 下载 1 MB 一次，读取超时 1 秒、采样预算 6 秒；完整长度、类型和响应状态匹配才通过。到预算即停止读取，单次底层连接/读取可能再等待其自身超时。速度包含 TLS 和首字节等待，是小文件快速采样速度，不能代表峰值带宽。', '',
            '优先完整下载通过的节点，再比较网页通过项数、连通通过项数、204 中位延迟、下载速度及 TCP 延迟。地区和非机房组仅从快速下载通过的节点选择，各地区最多 30 个；非机房最多 30 个独立出口，且必须明确 hosting=false。', '',
            '手机仅显示八个分组：全局选择、综合优选、非机房 IP、按地区选择、TCP通、TCP不通、TCP未验证、全部节点。每地区前 30 个按国家排列在同一个地区组。各网站、204 和 trace 的细分结果放在报告；全部可解析节点保留，刷新原订阅即可；所有延迟及速度来自 GitHub 云端，仍需手机对照。', '',
            '## 服务状态', '', '| 服务 | 当前接入 | 状态说明 |', '|---|---|---|']
    for name, service in services.items():
        rows.append(f'| [{name}]({service["url"]}) | {service["mode"]} | {service.get("reason", "公开 TCPing API，最多 5 次请求/秒")} |')
    rows += ['', '表格仅展示进入海外网站检测的节点；全部节点及跳过原因见 [JSON 完整报告](连通性报告.json)。', '']
    rows += ['', '## 手机对照', '', '刷新原订阅，进入“🚀 全局选择”，优先选择“⭐ 综合优选”；也可对照三个 TCP 分类，204 未通过的节点在名称中注明。反馈节点编号和手机实际体验。', '',
             '| 编号 | 入口 | TCP 分类 | 地区 | HTTPS204（三轮） | ' + ' | '.join(POST_SITES) + ' | 快速下载 |',
             '|' + '---|' * (6 + len(POST_SITES))]
    for record in records:
        if not record.get('websites'):
            continue
        results = record['websites']
        scores = []
        for item in [record.get('precheck')] + [results.get(label) for label in POST_SITES]:
            score = f'{item["passed_count"]}/{item["round_count"]} {LABELS[item["status"]]}' if item else '未测'
            if item and item.get('median_elapsed_ms') is not None:
                score += f'，中位 {item["median_elapsed_ms"]}ms / 最大 {item.get("max_elapsed_ms", "未记录")}ms'
            scores.append(score)
        downloaded = record.get('download') or {}
        scores.append(f'{downloaded["speed_mib_s"]:.3f} MiB/s' if downloaded.get('status') == 'passed' else LABELS.get(downloaded.get('status'), '未测'))
        country = (record.get('exit') or {}).get('country_code')
        rows.append(f'| {record["id"][2:]} | {record["server"]}:{record["port"]} | {LABELS[record["entry"]["status"]]} | {s.COUNTRIES.get(country, country) or "未确认"} | ' + ' | '.join(scores) + ' |')
    if rejected:
        rows += ['', '内核或手机兼容性校验未通过的节点未写入订阅，编号：' + '、'.join(rejected)]
    Path('连通性报告.md').write_text('\n'.join(rows) + '\n')
    print(f'分阶段分类完成，配置校验通过；204 {report["precheck_counts"]}；TCP {counts}；下载 {report["download_counts"]}', flush=True)


if __name__ == '__main__':
    main()
