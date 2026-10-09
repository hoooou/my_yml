#!/usr/bin/env python3
"""Classify every subscription endpoint and repeat webpages only for reachable nodes."""
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
from mobile_pilot import check_sites, SITES, UDP_TYPES

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


def probe_pipeline(nodes, binary, root, probe=probe_xxapi, site_check=check_sites, interval=.2, workers=16):
    if not nodes:
        return [], 0
    listeners, ports = s.make_listeners({'id': n['name']} for n in nodes)
    checked, jobs, lock = {}, [], threading.Lock()
    def completed(job):
        if job.exception() is not None:
            return
        record = job.result()
        with lock:
            checked[record['id']] = record
            if len(checked) % 20 == 0:
                print(f'流水线网页完成 {len(checked)}，已提交 {len(jobs)}；TCP 探测同时运行，每站 3 轮', flush=True)
    with s.Core(binary, root, nodes, listeners), futures.ThreadPoolExecutor(max_workers=workers) as pool:
        def submit(record):
            if record['entry']['status'] == 'passed':
                job = pool.submit(check_repeated, ports[record['id']], record, site_check=site_check)
                jobs.append(job)
                job.add_done_callback(completed)
        records, endpoints = classify_all(nodes, probe=probe, pace=Pace(interval), on_record=submit)
        for job in futures.as_completed(jobs):
            job.result()  # Propagate errors; never silently publish an incomplete shard.
    print(f'流水线完成：TCP 入口 {endpoints}，网页节点 {len(checked)}', flush=True)
    return [checked.get(r['id'], r) for r in records], endpoints


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
        if part['endpoint_count'] != len({endpoint_key(n) for n in subset if tcp_supported(n)}):
            raise ValueError('TCP 入口统计不完整')
        rows = part['records']
        if len(rows) != len(expected) or {r['id'] for r in rows} != expected:
            raise ValueError('分片存在漏测、重复或串片节点')
        for record in rows:
            if record['entry']['status'] == 'passed' and (not record.get('websites') or any(
                    record['websites'].get(site, {}).get('round_count') != 3 or
                    len(record['websites'].get(site, {}).get('attempts', [])) != 3 for site in SITES)):
                raise ValueError('通过节点缺少完整网页复测')
            combined[record['id']] = record
    return [combined[n['name']] for n in bundle['nodes']], sum(p['endpoint_count'] for p in parts)


def summarize_rounds(rounds):
    summarized = {}
    for label in SITES:
        attempts = [row[label] for row in rounds]
        passed = sum(a['status'] == 'passed' for a in attempts)
        status = ('passed' if passed == len(rounds) else 'needs_review' if any(a['status'] == 'needs_review' for a in attempts)
                  else 'unstable' if passed else 'failed')
        delays = [a['elapsed_ms'] for a in attempts if a.get('elapsed_ms') is not None and a['status'] == 'passed']
        summarized[label] = {'status': status, 'passed_count': passed, 'round_count': len(rounds),
                              'median_elapsed_ms': round(statistics.median(delays), 1) if delays else None,
                              'attempts': attempts}
    return summarized


def check_repeated(port, record, rounds=3, site_check=check_sites):
    if record['entry']['status'] != 'passed':
        return record
    record = copy.deepcopy(record)
    outcomes = []
    for index in range(rounds):
        outcomes.append(site_check(port))
        if index + 1 < rounds:
            time.sleep(1)
    record['websites'] = summarize_rounds(outcomes)
    try:
        record['exit'] = s.query_exit(port, {'id': record['id']})
    except (s.requests.RequestException, ValueError, KeyError):
        record['exit_reason'] = '出口 IP/地区未确认'
    return record


def website_count(record):
    return sum(v['status'] == 'passed' for v in (record.get('websites') or {}).values())


def render_comparison(base, records, mapping):
    """Keep all parseable samples for the user's local positive/negative comparison."""
    config = {key: copy.deepcopy(base[key]) for key in (
        'mixed-port', 'allow-lan', 'mode', 'log-level', 'external-controller', 'dns', 'rules', 'rule-providers') if key in base}
    config.setdefault('dns', {})
    references = {rule.split(',')[1] for rule in config.get('rules', []) if rule.startswith('RULE-SET,')}
    config['rule-providers'] = {k: v for k, v in config.get('rule-providers', {}).items() if k in references}
    proxies, classified, regions = [], {v: [] for v in ('passed', 'failed', 'unknown')}, {}
    ranked = sorted(records, key=lambda r: (-website_count(r), r['entry'].get('latency_ms', math.inf), r['id']))
    non_dc, seen_ips = [], set()
    for record in ranked:
        region_code = (record.get('exit') or {}).get('country_code')
        region = s.COUNTRIES.get(region_code, region_code) if region_code else '地区未确认'
        status = record['entry']['status']
        webpages = f'网页{website_count(record)}/3项通过' if record.get('websites') else '未测网站'
        name = f"{record['id'][2:]} | {region} | TCP{LABELS[status]} | {webpages}"
        record['name'] = name
        node = copy.deepcopy(mapping[record['id']]); node['name'] = name; proxies.append(node)
        classified[status].append(name)
        if region_code and status == 'passed' and website_count(record):
            regions.setdefault(region, []).append(name)
        ip = (record.get('exit') or {}).get('exit_ip')
        if (status == 'passed' and website_count(record) and record.get('ip_type', {}).get('hosting') is False
                and record['ip_type'].get('status') == 'success' and ip and ip not in seen_ips and len(non_dc) < 30):
            non_dc.append(name); seen_ips.add(ip)
    stable = [r['name'] for r in ranked if r['entry']['status'] == 'passed' and website_count(r) == 3]
    fallback = '✅ 三站稳定' if stable else '📶 TCP通' if classified['passed'] else '🔎 TCP未验证' if classified['unknown'] else '⛔ TCP不通'
    def group(name, names):
        return {'name': name, 'type': 'select', 'proxies': names or ['REJECT']}
    region_names = list(regions)
    config['proxies'] = proxies
    config['proxy-groups'] = [
        group('🚀 全局选择', list(dict.fromkeys([fallback, '✅ 三站稳定', '📶 TCP通', '⛔ TCP不通', '🔎 TCP未验证',
                                              '🌐 Google', '📺 YouTube', '💬 ChatGPT', '🏠 非机房 IP', '🎯 手动选择', 'DIRECT'] + region_names))),
        group('✅ 三站稳定', stable), group('📶 TCP通', classified['passed']), group('⛔ TCP不通', classified['failed']),
        group('🔎 TCP未验证', classified['unknown']), group('🎯 手动选择', [n['name'] for n in proxies]),
        group('🏠 非机房 IP', non_dc),
    ]
    for label, name in [('Google', '🌐 Google'), ('YouTube', '📺 YouTube'), ('ChatGPT', '💬 ChatGPT')]:
        config['proxy-groups'].append(group(name, [r['name'] for r in ranked if r.get('websites') and r['websites'][label]['status'] == 'passed']))
    config['proxy-groups'] += [group(name, names[:30]) for name, names in regions.items()]
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
        endpoint_count = len({endpoint_key(n) for n in nodes if tcp_supported(n)})
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
        print(f'全量节点 {input_count}，内核可解析 {len(nodes)}；已准备流水线输入，不运行下载测速', flush=True)
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
        records, endpoint_count = probe_pipeline(subset, binary, root, interval=.2 * args.shard_count)
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
    report = {'updated_at': now, 'scope': bundle['scope'],
              'measurements_updated_at': bundle.get('measurements_updated_at', now),
              'publication_mode': 'compatibility_repair' if args.phase == 'repair' else 'full',
              'mobile_rejections': bundle.get('mobile_rejections', {}),
              'pipeline': True, 'parallel_shards': bundle.get('parallel_shards', args.shard_count if args.phase == 'publish' else 1),
              'website_workers_per_shard': 16, 'parallel_sites_per_node': 3,
              'download_test': False, 'website_rounds': 3, 'input_unique_count': input_count,
              'parseable_count': len(nodes), 'invalid_node_ids': rejected, 'unique_tcp_endpoints': endpoint_count,
              'entry_counts': counts, 'website_tested_count': len(reachable),
              'three_sites_stable': sum(website_count(r) == 3 for r in records),
              'services': services, 'sources': sources, 'nodes': records}
    Path('优选配置.yaml').write_text(f'# 全量 TCP 分类与网页 3 轮复测；{now}；未测下载速度\n' + candidate.read_text())
    Path('连通性报告.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    rows = ['# 节点 TCP 连通性与网页复测', '', f'发布时间：{now}；检测数据时间：{report["measurements_updated_at"]}', '',
            f'去重节点 {input_count}；内核可解析 {len(nodes)}；不同 TCP 入口 {endpoint_count}。', '',
            f'TCP 通 {counts["passed"]}，不通 {counts["failed"]}，未验证 {counts["unknown"]}；网站复测 {len(reachable)} 个节点，三站全部稳定 {report["three_sites_stable"]} 个。', '',
            '不进行下载测速。全部可解析节点保留在订阅，方便手机对照“TCP通”“TCP不通”“TCP未验证”；地区和非机房分组最多各 30 个。', '',
            'TCP 结果是小小 API 探测点单次真实端口连接结果；探测点运营商未公开，不代表移动或本地必然可用。共享主机和端口共用入口结果，不同密码与协议节点分别复测网站。UDP、接口超时、限流、错误和目标不匹配归入未验证。', '',
            f'TCP 与网站采用流水线并行：入口一通过即提交网页任务，不等待全部 TCP 完成。本轮 {report["parallel_shards"]} 个 Actions 分片，每个分片最多同时复测 16 个节点，三个网站同时请求，同一网站的三轮依次执行。', '',
            '仅 TCP 通的节点检查 Google、YouTube、ChatGPT，每站独立 3 轮，全部成功才加入该站分组。只读取网页前 16 KB，网页通过不代表视频播放或 ChatGPT 对话已验证；403/验证码/风控记为需人工复核。地区来自实际 Cloudflare 出口，无法取得则名称显示地区未确认。', '',
            '## 服务状态', '', '| 服务 | 当前接入 | 状态说明 |', '|---|---|---|']
    for name, service in services.items():
        rows.append(f'| [{name}]({service["url"]}) | {service["mode"]} | {service.get("reason", "公开 TCPing API，最多 5 次请求/秒")} |')
    rows += ['', '## 手机对照', '', '刷新原订阅，进入“🚀 全局选择”，选择对应分类，再在分类组内选单个节点。反馈编号、云端分类、本地能否连接，以及 Google、YouTube 播放和 ChatGPT 实际对话是否可用。', '',
             '| 编号 | 入口 | TCP 分类 | 地区 | Google | YouTube | ChatGPT |', '|---|---|---|---|---|---|---|']
    for record in records:
        results = record.get('websites') or {}
        scores = [f'{results[label]["passed_count"]}/3 {LABELS[results[label]["status"]]}' if label in results else '未测' for label in SITES]
        country = (record.get('exit') or {}).get('country_code')
        rows.append(f'| {record["id"][2:]} | {record["server"]}:{record["port"]} | {LABELS[record["entry"]["status"]]} | {s.COUNTRIES.get(country, country) or "未确认"} | ' + ' | '.join(scores) + ' |')
    if rejected:
        rows += ['', '内核或手机兼容性校验未通过的节点未写入订阅，编号：' + '、'.join(rejected)]
    Path('连通性报告.md').write_text('\n'.join(rows) + '\n')
    print(f'全量分类完成，配置校验通过；{counts}；不含下载测速', flush=True)


if __name__ == '__main__':
    main()
