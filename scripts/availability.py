#!/usr/bin/env python3
"""Stage HTTPS 204, domestic TCP, overseas pages/trace and a quick download."""
import argparse
import concurrent.futures as futures
import copy
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import statistics
import subprocess
import threading
import time

import yaml
import select_nodes as s
from mobile_pilot import check_site, check_sites, SITES, PAGE_SITES, OVERSEAS_SITES, DOMESTIC_SITES, CONNECTIVITY_SITES, POST_SITES, SITE_WORKERS, WEB_USER_AGENT, UDP_TYPES
from routing import optimize_routing
import ip_reputation
import app_tls
import published_history
import high_speed
import medium_speed
import stability
from attempt_report import write_attempt
from mobile_pilot import MAX_TTFB_MS, MAX_SAMPLE_MS, PAGE_SAMPLE_LIMITS, confirmed_cloudflare_challenge

XXAPI = 'https://v2.xxapi.cn/api/tcping'
LABELS = {'passed': '通', 'failed': '不通', 'unknown': '未验证',
          'unstable': '波动', 'verification_required': 'CF需验证', 'needs_review': '需人工复核', 'skipped': '未测', 'slow': '响应慢'}
WEBSITE_ROUNDS = 3
CORE_SITES = ('Google', 'YouTube')
REQUIRED_SITES = ('Google', 'YouTube', 'ChatGPT', 'Gemini', 'GitHub',
                  'Wikipedia', 'Reddit', 'X', 'Instagram', 'Telegram', 'Discord', 'Facebook')
REQUIRED_TRACES = ('ClaudeTrace',)
CORE_MEDIAN_MS = 1500
CORE_TAIL_MS = 3000
CORE_JITTER_MS = 1500
REGIONAL_GROUP = '🌏 台湾／新加坡'
REGIONAL_COUNTRIES = ('TW', 'SG')
REGIONAL_MEDIAN_MS = 3000
REGIONAL_TAIL_MS = 5000
REGIONAL_JITTER_MS = 3000


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
HIGH_DOWNLOAD_BYTES = high_speed.BYTES
HIGH_DOWNLOAD_BUDGET = high_speed.BUDGET
HIGH_DOWNLOAD_WORKERS = high_speed.WORKERS
HIGH_DOWNLOAD_URL = high_speed.URLS[0]


def precheck_204(port):
    outcomes = [{'Google204': check_site(port, 'Google204', SITES['Google204'], timeout=(2, 3))}
                for _ in range(3)]
    return summarize_rounds(outcomes, labels=('Google204',))['Google204']


def download_sample(port, byte_count, budget, url=None):
    """One complete bounded sample; speed includes TLS and first byte."""
    url = url or f'https://speed.cloudflare.com/__down?bytes={byte_count}'
    label = f'{byte_count // 1_000_000} MB'
    started = time.perf_counter()
    received = 0
    result = {'status': 'failed', 'url': url, 'requested_bytes': byte_count,
              'budget_seconds': budget, 'speed_mib_s': None}
    request_headers = high_speed.request_headers(url)
    if url == medium_speed.URL:
        request_headers['Referer'] = 'https://speed.cloudflare.com/'
    with s.session() as client:
        client.proxies = {'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}
        try:
            with client.get(url, stream=True, timeout=(2, 1), allow_redirects=False,
                            headers={'Accept-Encoding': 'identity', 'Cache-Control': 'no-cache', 'User-Agent': WEB_USER_AGENT,
                                     **request_headers}) as response:
                result['http_status'] = response.status_code
                result['response_length'] = response.headers.get('Content-Length')
                result['response_type'] = response.headers.get('Content-Type')
                result['response_encoding'] = response.headers.get('Content-Encoding', 'identity')
                result['request_headers'] = request_headers
                if (response.status_code != 200 or response.url != url
                        or response.headers.get('Content-Length') != str(byte_count)
                        or response.headers.get('Content-Type', '').split(';')[0] != 'application/octet-stream'
                        or response.headers.get('Content-Encoding', 'identity') != 'identity'):
                    return {**result, 'reason': '下载状态、文件长度或类型不匹配'}
                # read1 returns available data without waiting to fill a large chunk.
                while received <= byte_count and time.perf_counter() - started < budget:
                    chunk = response.raw.read1(16384)
                    if not chunk:
                        break
                    received += len(chunk)
                elapsed = time.perf_counter() - started
                if received != byte_count or elapsed > budget:
                    return {**result, 'reason': f'未在时间预算内完整下载 {label}', 'received_bytes': received,
                            'elapsed_ms': round(elapsed * 1000, 1)}
                elapsed_ms = max(round(elapsed * 1000, 1), .1)
                return {**result, 'status': 'passed', 'reason': f'{label} 完整下载；速度包含建连耗时',
                        'received_bytes': received, 'elapsed_ms': elapsed_ms,
                        'speed_mib_s': round(received / (elapsed_ms / 1000) / 1048576, 3)}
        except (s.requests.RequestException, OSError, s.requests.packages.urllib3.exceptions.HTTPError):
            return {**result, 'reason': f'{label} 下载连接、TLS 或读取失败', 'received_bytes': received}


def quick_download(port):
    return download_sample(port, DOWNLOAD_BYTES, DOWNLOAD_BUDGET)


def medium_speed_download(port):
    return download_sample(port, medium_speed.BYTES, medium_speed.BUDGET, medium_speed.URL)


def high_speed_download(port):
    # Each target gets a fresh session and its own deadline; keep both outcomes.
    return high_speed.summarize([download_sample(port, HIGH_DOWNLOAD_BYTES, HIGH_DOWNLOAD_BUDGET, url)
                                 for url in high_speed.URLS])


def probe_pipeline(nodes, binary, root, probe=probe_xxapi, precheck=precheck_204,
                   site_check=None, download=quick_download, large_download=high_speed_download, interval=.25, workers=16, medium_download=None):
    """Per-node stages are ordered, while different nodes overlap across stages."""
    medium_download = medium_download or medium_speed_download
    if not nodes:
        return [], 0
    site_check_is_default = site_check is None
    site_check = site_check or (lambda port: check_sites(port, POST_SITES))
    listeners, ports = s.make_listeners({'id': n['name']} for n in nodes)
    pace, lock, tcp_jobs = Pace(interval), threading.Lock(), {}
    medium_slots = threading.BoundedSemaphore(medium_speed.WORKERS)
    large_slots = threading.BoundedSemaphore(HIGH_DOWNLOAD_WORKERS)
    progress = {'done': 0, 'precheck': 0, 'tcp': 0, 'websites': 0, 'download': 0, 'medium_speed': 0, 'high_speed': 0}
    with s.Core(binary, root, nodes, listeners), futures.ThreadPoolExecutor(max_workers=10) as tcp_pool:
        def measure(node):
            port = ports[node['name']]
            record = {'id': node['name'], 'server': node['server'], 'port': node['port'], 'protocol': node['type'],
                      'entry': {'status': 'unknown', 'attempts': 0, 'reason': '204 未通过，未提交国内 TCP 检测'},
                      'websites': None, 'exit': None, 'download': {'status': 'skipped', 'reason': '未进入下载阶段'},
                      'app_tls': {'status': 'skipped', 'reason': '必过网站未通过，未提交应用TLS检查'},
                      'medium_speed_download': {'status': 'skipped', 'reason': '1 MB快测未通过，未提交5 MB测试'},
                      'high_speed_download': {'status': 'skipped', 'reason': '1 MB 快测未通过，未提交两轮100 MB测试'}}
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
                    rounds = [site_check(port)]
                    # Domestic pages and trace remain one round; overseas pages get three.
                    for _ in range(WEBSITE_ROUNDS - 1):
                        rounds.append(check_sites(port, {label: SITES[label] for label in OVERSEAS_SITES})
                            if site_check_is_default else site_check(port))
                    record['websites'] = summarize_rounds(rounds, labels=OVERSEAS_SITES)
                    record['websites'].update(summarize_rounds(rounds[:1],
                        labels=[label for label in POST_SITES if label not in OVERSEAS_SITES]))
                    record['websites_updated_at'] = s.datetime.now(s.TZ).isoformat(timespec='seconds')
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
                    if required_websites_passed(record):
                        record['app_tls'] = app_tls.check(port)
                        if app_tls.passed(record['app_tls']):
                            record['download'] = download(port)
                            if record['download']['status'] == 'passed':
                                with medium_slots:
                                    record['medium_speed_download'] = medium_download(port)
                                record['medium_speed_updated_at'] = s.datetime.now(s.TZ).isoformat(timespec='seconds')
                                with large_slots:
                                    record['high_speed_download'] = large_download(port)
                        else:
                            record['download']['reason'] = 'ChatGPT应用TLS校验未全部通过，跳过下载'
                    else:
                        record['download']['reason'] = '12个必过页面未满足三轮访问条件或Claude trace未通过，跳过下载'
            with lock:
                progress['done'] += 1
                progress['precheck'] += record['precheck']['status'] == 'passed'
                progress['tcp'] += record['entry']['status'] == 'passed'
                progress['websites'] += record['websites'] is not None
                progress['download'] += record['download']['status'] == 'passed'
                progress['medium_speed'] += medium_speed.passed(record['medium_speed_download'])
                progress['high_speed'] += record['high_speed_download']['status'] == 'passed'
                if progress['done'] % 100 == 0 or progress['done'] == len(nodes):
                    print(f'分阶段流水线 {progress["done"]}/{len(nodes)}：204通过 {progress["precheck"]}，TCP通过 {progress["tcp"]}，网站完成 {progress["websites"]}，1MB通过 {progress["download"]}，5MB通过 {progress["medium_speed"]}，100MB双轮通过 {progress["high_speed"]}', flush=True)
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
                    record['websites'].get(site, {}).get('round_count') != (WEBSITE_ROUNDS if site in OVERSEAS_SITES else 1) or
                    len(record['websites'].get(site, {}).get('attempts', [])) != (WEBSITE_ROUNDS if site in OVERSEAS_SITES else 1)
                    for site in POST_SITES)):
                raise ValueError('通过节点缺少海外三轮或国内/trace 单轮检测')
            if record.get('websites'):
                for label, item in record['websites'].items():
                    if any(a.get('status') == 'verification_required'
                           and not confirmed_cloudflare_challenge(label, a) for a in item['attempts']):
                        raise ValueError('Cloudflare 验证标记缺少可靠响应证据')
                    expected = summarize_rounds([{label: attempt} for attempt in item['attempts']], (label,))[label]
                    if any(item.get(key) != expected[key] for key in ('status', 'passed_count', 'median_elapsed_ms',
                            'p95_elapsed_ms', 'jitter_ms', 'median_ttfb_ms', 'failure_count', 'slow_count',
                            'accepted_count', 'verification_required_count')):
                        raise ValueError('网站汇总与逐轮响应结果不一致')
            if record['entry']['status'] == 'passed' and pre['status'] != 'passed':
                raise ValueError('节点未按阶段筛选')
            should_tls = record['entry']['status'] == 'passed' and required_websites_passed(record)
            tls = record.get('app_tls') or {}
            if tls.get('status') not in (('passed', 'failed') if should_tls else ('skipped',)):
                raise ValueError('应用TLS阶段漏测或顺序异常')
            if tls.get('status') == 'passed' and not app_tls.passed(tls):
                raise ValueError('应用TLS证书证据不完整，拒绝发布')
            should_download = should_tls and app_tls.passed(tls)
            if record.get('download', {}).get('status') not in (('passed', 'failed') if should_download else ('skipped',)):
                raise ValueError('下载阶段漏测或顺序异常')
            if record.get('download', {}).get('status') == 'passed' and (
                    record['entry']['status'] != 'passed' or
                    not required_websites_passed(record) or not app_tls.passed(tls) or
                    record['download'].get('received_bytes') != DOWNLOAD_BYTES or
                    not 0 < record['download'].get('elapsed_ms', math.inf) <= DOWNLOAD_BUDGET * 1000):
                raise ValueError('下载结果不完整或节点未通过前置阶段')
            medium = record.get('medium_speed_download') or {}
            should_medium = record.get('download', {}).get('status') == 'passed'
            if medium.get('status') not in (('passed', 'failed') if should_medium else ('skipped',)):
                raise ValueError('5 MB阶段漏测或前置1 MB未通过')
            if should_medium and (medium.get('url') != medium_speed.URL
                    or medium.get('requested_bytes') != medium_speed.BYTES
                    or medium.get('budget_seconds') != medium_speed.BUDGET):
                raise ValueError('5 MB检测目标或预算不匹配')
            if medium.get('status') == 'passed' and not medium_speed.passed(medium):
                raise ValueError('5 MB结果不完整或超出预算')
            high = record.get('high_speed_download') or {}
            should_high = record.get('download', {}).get('status') == 'passed'
            if high.get('status') not in (('passed', 'failed') if should_high else ('skipped',)):
                raise ValueError('100 MB双轮阶段漏测或前置1 MB未通过')
            if should_high:
                attempts = high.get('attempts') or []
                if (high.get('version') != high_speed.VERSION or len(attempts) != len(high_speed.URLS)
                        or any(item.get('status') not in ('passed', 'failed')
                               or item.get('url') != url or item.get('requested_bytes') != HIGH_DOWNLOAD_BYTES
                               or item.get('budget_seconds') != HIGH_DOWNLOAD_BUDGET
                               for item, url in zip(attempts, high_speed.URLS))):
                    raise ValueError('100 MB双轮检测证据缺失或目标不匹配')
                expected = high_speed.summarize(attempts)
                if any(high.get(key) != expected[key] for key in ('status', 'round_count', 'passed_count',
                        'budget_seconds_per_round', 'speed_mib_s')):
                    raise ValueError('100 MB双轮汇总与采样不一致')
                if any(item['status'] == 'passed' and not high_speed.sample_passed(item, url)
                       for item, url in zip(attempts, high_speed.URLS)):
                    raise ValueError('100 MB下载结果不完整或超出预算')
            combined[record['id']] = record
    return [combined[n['name']] for n in bundle['nodes']], sum(p['endpoint_count'] for p in parts)


def summarize_rounds(rounds, labels=SITES):
    summarized = {}
    for label in labels:
        attempts = [row[label] for row in rounds]
        passed = sum(a['status'] == 'passed' for a in attempts)
        verified = sum(a.get('status') == 'verification_required'
                       and confirmed_cloudflare_challenge(label, a) for a in attempts)
        accepted = passed + verified
        status = ('passed' if passed == len(rounds)
                  else 'verification_required' if accepted == len(rounds)
                  else 'needs_review' if any(a['status'] == 'needs_review' for a in attempts)
                  else 'unstable' if accepted
                  else 'slow' if any(a['status'] == 'slow' for a in attempts) else 'failed')
        delays = [a['elapsed_ms'] for a in attempts if a.get('elapsed_ms') is not None and a['status'] == 'passed']
        all_delays = sorted(a['elapsed_ms'] for a in attempts if a.get('elapsed_ms') is not None)
        headers = [a['ttfb_ms'] for a in attempts if a.get('ttfb_ms') is not None]
        summarized[label] = {'status': status, 'passed_count': passed, 'round_count': len(rounds),
                              'verification_required_count': verified, 'accepted_count': accepted,
                              'median_elapsed_ms': round(statistics.median(delays), 1) if delays else None,
                              'max_elapsed_ms': max(delays) if delays else None,
                              'p95_elapsed_ms': all_delays[math.ceil(.95 * len(all_delays)) - 1] if all_delays else None,
                              'jitter_ms': round(max(all_delays) - min(all_delays), 1) if len(all_delays) > 1 else None,
                              'median_ttfb_ms': round(statistics.median(headers), 1) if headers else None,
                              'failure_count': sum(a['status'] == 'failed' for a in attempts),
                              'slow_count': sum(a['status'] == 'slow' for a in attempts),
                              'success_rate': round(passed / len(rounds), 4),
                              'attempts': attempts}
    return summarized



def website_count(record):
    results = record.get('websites') or {}
    return sum(results.get(label, {}).get('status') == 'passed' for label in OVERSEAS_SITES)


def domestic_count(record):
    results = record.get('websites') or {}
    return sum(results.get(label, {}).get('status') == 'passed' for label in DOMESTIC_SITES)


def overseas_reachable(record):
    results = record.get('websites') or {}
    return any(results.get(label, {}).get('status') == 'passed'
               for label in (*OVERSEAS_SITES, 'ChatGPTTrace', 'ClaudeTrace'))


def connectivity_count(record):
    results = record.get('websites') or {}
    return int((record.get('precheck') or results.get('Google204', {})).get('status') == 'passed') + sum(
        results.get(label, {}).get('status') == 'passed' for label in ('ChatGPTTrace', 'ClaudeTrace'))


def page_rounds_accepted(label, item, rounds=WEBSITE_ROUNDS):
    if item.get('round_count') != rounds:
        return False
    if item.get('status') == 'passed':
        return item.get('passed_count') == rounds
    attempts = item.get('attempts') or []
    return (item.get('status') == 'verification_required' and len(attempts) == rounds
            and all(a.get('status') == 'passed' or
                    (a.get('status') == 'verification_required'
                     and confirmed_cloudflare_challenge(label, a)) for a in attempts))


def website_access_count(record):
    sites = record.get('websites') or {}
    return sum(page_rounds_accepted(label, sites.get(label) or {}) for label in OVERSEAS_SITES)


def reclassify_cloudflare_records(records):
    """Reinterpret existing explicit header observations; never invent a new probe."""
    changed = 0
    for record in records:
        for label, item in (record.get('websites') or {}).items():
            attempts = copy.deepcopy(item.get('attempts') or [])
            affected = False
            for attempt in attempts:
                # Legacy restriction was emitted exclusively for cf-mitigated: challenge.
                if attempt.get('status') != 'needs_review' or attempt.get('restriction') != 'cloudflare_challenge':
                    continue
                candidate = {**attempt, 'classification_source': 'recorded_cloudflare_challenge'}
                if confirmed_cloudflare_challenge(label, candidate):
                    attempt.update(classification_source='recorded_cloudflare_challenge',
                        status='verification_required',
                        reason='明确 Cloudflare 人机验证；按用户策略认可网站可达，实际页面未验证')
                    changed += 1
                    affected = True
            if affected:
                record['websites'][label] = summarize_rounds([{label: a} for a in attempts], (label,))[label]
    return changed


def required_websites_passed(record):
    return all(page_rounds_accepted(label, (record.get('websites') or {}).get(label) or {})
        for label in REQUIRED_SITES) and all(
        (record.get('websites') or {}).get(label, {}).get('status') == 'passed'
        and record['websites'][label].get('round_count') == 1
        and record['websites'][label].get('passed_count') == 1
        for label in REQUIRED_TRACES)


def web_quality_eligible(record):
    if 'stability' in record and not stability.quality_passed(record['stability'], CORE_MEDIAN_MS, CORE_TAIL_MS, CORE_JITTER_MS):
        return False
    if not required_websites_passed(record) or not app_tls.passed(record.get('app_tls')):
        return False
    sites = record.get('websites') or {}
    for label in CORE_SITES:
        item = sites.get(label) or {}
        if (item.get('status') != 'passed' or item.get('round_count') != WEBSITE_ROUNDS
                or item.get('passed_count') != WEBSITE_ROUNDS):
            return False
        for field, limit in (('median_elapsed_ms', CORE_MEDIAN_MS), ('p95_elapsed_ms', CORE_TAIL_MS),
                             ('jitter_ms', CORE_JITTER_MS)):
            value = item.get(field)
            if not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= limit:
                return False
    return website_access_count(record) >= math.ceil(len(OVERSEAS_SITES) / 2)


def web_rank_metrics(record):
    sites = record.get('websites') or {}
    core = [sites.get(label) or {} for label in CORE_SITES]
    core_metrics = tuple(max((item.get(field) if item.get(field) is not None else math.inf) for item in core)
                         for field in ('p95_elapsed_ms', 'median_elapsed_ms', 'jitter_ms'))
    stable = [sites[label] for label in OVERSEAS_SITES if (sites.get(label) or {}).get('status') == 'passed']
    overall_metrics = tuple(statistics.median([item[field] for item in stable if item.get(field) is not None])
        if any(item.get(field) is not None for item in stable) else math.inf
        for field in ('p95_elapsed_ms', 'median_elapsed_ms', 'jitter_ms'))
    return core_metrics + overall_metrics


def regional_eligible(record):
    """A regional exception permits slower pages, never failed access or downloads."""
    if 'stability' in record and not stability.quality_passed(record['stability'], REGIONAL_MEDIAN_MS, REGIONAL_TAIL_MS, REGIONAL_JITTER_MS):
        return False
    if (not required_websites_passed(record)
            or not app_tls.passed(record.get('app_tls'))
            or (record.get('exit') or {}).get('country_code') not in REGIONAL_COUNTRIES
            or record.get('exit_consistent') is False
            or record['entry']['status'] != 'passed'
            or (record.get('download') or {}).get('status') != 'passed'):
        return False
    pre = record.get('precheck') or {}
    if pre.get('status') != 'passed' or pre.get('round_count') != 3 or pre.get('passed_count') != 3:
        return False
    for label in CORE_SITES:
        item = (record.get('websites') or {}).get(label) or {}
        if (item.get('status') != 'passed' or item.get('round_count') != WEBSITE_ROUNDS
                or item.get('passed_count') != WEBSITE_ROUNDS):
            return False
        for field, limit in (('median_elapsed_ms', REGIONAL_MEDIAN_MS),
                ('p95_elapsed_ms', REGIONAL_TAIL_MS), ('jitter_ms', REGIONAL_JITTER_MS)):
            value = item.get(field)
            if not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= limit:
                return False
    return True


def rank_key(record):
    pre = record.get('precheck') or {}
    temporal = record.get('stability') or {}
    values = [x['sites'][label]['elapsed_ms'] for x in temporal.get('attempts', [])
        for label in CORE_SITES if isinstance(x.get('sites', {}).get(label, {}).get('elapsed_ms'), (int, float))]
    temporal_tail = max(values) if values else math.inf
    downloaded = record.get('download') or {}
    return (downloaded.get('status') != 'passed', not web_quality_eligible(record), temporal_tail,
            *web_rank_metrics(record), -website_count(record), -connectivity_count(record),
            pre.get('median_elapsed_ms') if pre.get('median_elapsed_ms') is not None else math.inf,
            -(downloaded.get('speed_mib_s') or 0), record['entry'].get('latency_ms', math.inf), record['id'])


def high_speed_rank_key(record):
    delay = (record.get('precheck') or {}).get('median_elapsed_ms')
    return (-((record.get('high_speed_download') or {}).get('speed_mib_s') or 0),
            delay if delay is not None else math.inf,
            -website_count(record), record['id'])


def high_speed_eligible(record):
    """Historical one-target samples cannot qualify for the two-target policy."""
    return ((record.get('download') or {}).get('status') == 'passed'
            and high_speed.passed(record.get('high_speed_download') or {}))


def recheck_websites(records, mapping, binary, root):
    """Recheck the small download-passed pool without rerunning TCP or downloads."""
    candidates = [r for r in records if r['id'] in mapping
                  and (r.get('download') or {}).get('status') == 'passed']
    if not candidates:
        raise RuntimeError('没有可复测的已发布节点；保留旧订阅')
    listeners, ports = s.make_listeners(candidates)
    done, lock = 0, threading.Lock()
    with s.Core(binary, root, [mapping[r['id']] for r in candidates], listeners):
        def measure(record):
            nonlocal done
            port = ports[record['id']]
            rounds = [check_sites(port, {label: SITES[label] for label in OVERSEAS_SITES})
                      for _ in range(WEBSITE_ROUNDS)]
            # Preserve old domestic/trace results and their original measurement times.
            record.setdefault('websites', {}).update(summarize_rounds(rounds, OVERSEAS_SITES))
            record['websites_updated_at'] = s.datetime.now(s.TZ).isoformat(timespec='seconds')
            record['app_tls'] = app_tls.check(port) if required_websites_passed(record) else {'status': 'skipped'}
            with lock:
                done += 1
                if done % 10 == 0 or done == len(candidates):
                    print(f'海外请求响应三轮复测 {done}/{len(candidates)}', flush=True)
        with futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(measure, candidates))
    (root / 'web-recheck-results.json').write_text(json.dumps(records, ensure_ascii=False))
    print('海外响应质量复测完成：综合合格 ' + str(sum(web_quality_eligible(r) for r in candidates))
          + '/' + str(len(candidates)), flush=True)
    return len(candidates)


def recheck_medium_download(records, mapping, binary, root):
    candidates = [r for r in records if r['id'] in mapping
                  and r.get('download', {}).get('status') == 'passed']
    if not candidates:
        raise RuntimeError('没有1 MB已通过节点，保留旧订阅')
    listeners, ports = s.make_listeners(candidates)
    with s.Core(binary, root, [mapping[r['id']] for r in candidates], listeners):
        def measure(record):
            record['medium_speed_download'] = medium_speed_download(ports[record['id']])
            record['medium_speed_updated_at'] = s.datetime.now(s.TZ).isoformat(timespec='seconds')
        with futures.ThreadPoolExecutor(max_workers=medium_speed.WORKERS) as pool:
            list(pool.map(measure, candidates))
    print(f'已有1 MB通过节点补测5 MB完成：{len(candidates)}个，完整通过{sum(medium_speed.passed(r["medium_speed_download"]) for r in candidates)}个', flush=True)
    return len(candidates)


def limit_hong_kong(records):
    """Keep ranked Hong Kong candidates up to 30; other regions are unlimited."""
    selected, hong_kong_count = [], 0
    for record in records:
        if (record.get('exit') or {}).get('country_code') == 'HK':
            if hong_kong_count >= 30:
                continue
            hong_kong_count += 1
        selected.append(record)
    return selected


def render_comparison(base, records, mapping, require_stability=False):
    """Publish the strict pool and an explicitly authorized regional exception."""
    # Clear former publication names before renumbering. Otherwise an excluded
    # node can collide with a retained node's new name in report membership.
    for record in records:
        if record['id'] in mapping:
            record.pop('name', None)
    config = {key: copy.deepcopy(base[key]) for key in (
        'mixed-port', 'allow-lan', 'mode', 'log-level', 'external-controller', 'dns', 'rules', 'rule-providers') if key in base}
    optimize_routing(config)
    proxies = []
    # The slower regional pool is selectable only in its own group.
    ranked = limit_hong_kong(sorted((r for r in records if r['id'] in mapping
        and (stability.passed(r.get('stability')) if require_stability or 'stability' in r else True)
        and r['entry']['status'] == 'passed'
        and (r.get('download') or {}).get('status') == 'passed'
        and (web_quality_eligible(r) or regional_eligible(r))), key=rank_key))
    strict = [r for r in ranked if web_quality_eligible(r)]
    strict_ids = {r['id'] for r in strict}
    region_numbers = {}
    non_dc, seen_ips = [], set()
    for record in ranked:
        region_code = (record.get('exit') or {}).get('country_code')
        region = s.COUNTRIES.get(region_code, region_code) if region_code else '地区未确认'
        pre = record.get('precheck') or {}
        core_latencies = [(record.get('websites') or {}).get(label, {}).get('median_elapsed_ms') for label in CORE_SITES]
        if stability.passed(record.get('stability')):
            core_latencies = [stability.core_metrics(record['stability'])[label]['median_ms'] for label in CORE_SITES]
        latency = max(core_latencies) if all(isinstance(v, (float, int)) and math.isfinite(v) for v in core_latencies) else None
        if latency is None:
            latency = pre.get('median_elapsed_ms') if pre.get('status') == 'passed' else None
        delay = (f'{latency:.0f}ms'
            if isinstance(latency, (int, float)) and math.isfinite(latency) else '?ms')
        measured = (record.get('high_speed_download') if high_speed_eligible(record) else
                    record.get('medium_speed_download') if medium_speed.passed(record.get('medium_speed_download') or {})
                    else record.get('download'))
        speed = (measured or {}).get('speed_mib_s')
        bandwidth = (f'{speed * 1048576 * 8 / 1000000:.0f}Mbps'
            if (measured or {}).get('status') == 'passed' and isinstance(speed, (int, float))
            and math.isfinite(speed) and speed > 0 else '?Mbps')
        housing = {'住宅候选': '住宅', '机房': '非住宅', '移动网络': '非住宅',
                   '非机房': '住宅未知', '住宅未知': '住宅未知'}[ip_reputation.residence_label(record)]
        info = record.get('ip_reputation') or {}
        purity = info.get('network_purity_score') if info.get('status') == 'success' else None
        purity_text = (f'纯净度{purity:.1f}%' if isinstance(purity, (int, float))
                       and math.isfinite(purity) else '纯净度未知')
        region_numbers[region] = region_numbers.get(region, 0) + 1
        name = '|'.join([f'{region}{region_numbers[region]:02d}', delay, bandwidth, housing, purity_text])
        record['name'] = name
        record['name_latency_source'] = ('time_spaced_Google_YouTube_slower_median' if stability.passed(record.get('stability')) else 'Google_YouTube_slower_median') if all(isinstance(v, (float, int)) and math.isfinite(v) for v in core_latencies) else 'HTTPS204_median'
        record['name_bandwidth_source'] = ('100MB_double_minimum' if high_speed_eligible(record) else
            '5MB' if medium_speed.passed(record.get('medium_speed_download') or {}) else '1MB')
        node = copy.deepcopy(mapping[record['id']]); node['name'] = name; proxies.append(node)
        ip = (record.get('exit') or {}).get('exit_ip')
        if (record['id'] in strict_ids and record.get('exit_consistent') is not False
                and record.get('ip_type', {}).get('hosting') is False
                and record['ip_type'].get('status') == 'success' and ip and ip not in seen_ips):
            non_dc.append(record); seen_ips.add(ip)
    non_dc = [r['name'] for r in non_dc]
    high = [r['name'] for r in sorted(strict, key=high_speed_rank_key) if high_speed_eligible(r)]
    medium = [r['name'] for r in sorted(ranked, key=lambda r: (
        -((r.get('medium_speed_download') or {}).get('speed_mib_s') or 0), r['id']))
        if medium_speed.passed(r.get('medium_speed_download') or {})]
    recommended = [r['name'] for r in strict]
    regional = [r['name'] for r in ranked if regional_eligible(r)]
    def group(name, names):
        return {'name': name, 'type': 'select', 'proxies': names or ['REJECT']}
    config['proxies'] = proxies
    choices = ['⭐ 综合优选', medium_speed.GROUP, '⚡ 高速下载', '🏠 非机房 IP', REGIONAL_GROUP, 'DIRECT']
    if not recommended and regional:
        choices.remove(REGIONAL_GROUP); choices.insert(0, REGIONAL_GROUP)
    config['proxy-groups'] = [
        group('🚀 全局选择', choices),
        group('⭐ 综合优选', recommended), group(medium_speed.GROUP, medium),
        group('⚡ 高速下载', high), group('🏠 非机房 IP', non_dc), group(REGIONAL_GROUP, regional),
    ]
    if mobile_control_paths(config):
        raise ValueError('配置包含解码后的控制字符，拒绝发布到手机')
    return config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--phase', choices=('all', 'prepare', 'probe', 'publish', 'repair', 'web-recheck', 'medium-recheck', 'stability-recheck'), default='all')
    parser.add_argument('--sample', help='Optional fixture; default pulls ALL subscriptions')
    parser.add_argument('--work-dir', default='.node-work/availability')
    parser.add_argument('--shard-index', type=int, default=0)
    parser.add_argument('--shard-count', type=int, default=4)
    parser.add_argument('--results-dir', default='.node-work/shards')
    parser.add_argument('--refresh-ip-reputation', action='store_true', help='Refresh optional IP metadata in repair mode')
    args = parser.parse_args()
    root = Path(args.work_dir).resolve(); root.mkdir(parents=True, exist_ok=True)
    binary = str(Path(args.mihomo).resolve())
    bundle_path = root / 'bundle.json'
    if args.phase in ('repair', 'web-recheck', 'medium-recheck', 'stability-recheck'):
        previous = json.loads(Path('连通性报告.json').read_text())
        published = yaml.safe_load(Path('优选配置.yaml').read_text())
        by_name = {n['name']: n for n in published['proxies']}
        # Published YAML deliberately excludes rejected nodes; reports still audit them.
        nodes = [{**by_name[r['name']], 'name': r['id']} for r in previous['nodes']
                 if r.get('name') in by_name]
        nodes, mobile_rejections = filter_mobile_nodes(nodes)
        records = [r for r in previous['nodes'] if r['id'] not in mobile_rejections]
        reclassified_count = reclassify_cloudflare_records(records)
        if not nodes:
            raise RuntimeError('没有手机可安全读取的节点；保留旧订阅')
        bundle = {'base': yaml.safe_load(Path('聚合配置.yaml').read_text()), 'nodes': nodes,
                  'metadata': {r['id']: {'sources': r.get('sources', [])} for r in records},
                  'sources': previous['sources'], 'input_count': previous['input_unique_count'],
                  'historical_candidates': previous.get('historical_candidates', {}),
                  'rejected': sorted(set(previous['invalid_node_ids']) | set(mobile_rejections)),
                  'mobile_rejections': {**previous.get('mobile_rejections', {}), **mobile_rejections},
                  'services': previous['services'], 'scope': previous['scope'],
                  'parallel_shards': previous.get('parallel_shards', 1),
                  'measurements_updated_at': previous.get('measurements_updated_at', previous['updated_at']),
                  'parseable_count': previous.get('parseable_count', len(previous['nodes'])) - len(mobile_rejections),
                  'total_unique_tcp_endpoints': previous.get('total_unique_tcp_endpoints',
                      len({endpoint_key(n) for n in nodes if tcp_supported(n)}))}
        endpoint_count = previous.get('unique_tcp_endpoints', len({endpoint_key(n) for n in nodes if tcp_supported(n)}))
        print(f'按当前规则重建已有结果：剔除 {len(mobile_rejections)} 个损坏节点，保留 {len(nodes)} 个；本模式 {args.phase}', flush=True)
    elif args.phase in ('all', 'prepare'):
        base = yaml.safe_load(Path('聚合配置.yaml').read_text())
        historical = {'added_count': 0, 'refs': [], 'measurement_reuse': False, 'status': 'fixture'}
        if args.sample:
            samples = yaml.safe_load(Path(args.sample).read_text())['samples']
            nodes = [{**r['node'], 'name': r['id']} for r in samples]
            metadata, sources = {}, []
        else:
            nodes, metadata, sources = s.collect(base, root, extra_sources=s.load_sources(Path('节点来源.yaml')))
            if not nodes:
                raise RuntimeError('没有来源节点；保留已发布订阅')
            nodes, metadata, historical = published_history.collect(nodes, metadata)
        input_count = len(nodes)
        if not nodes:
            raise RuntimeError('没有来源节点；保留已发布订阅')
        nodes, mobile_rejections = filter_mobile_nodes(nodes)
        if not nodes:
            raise RuntimeError('全部节点未通过手机兼容性检查；保留旧订阅')
        nodes, rejected = s.Core(binary, root, nodes).validate_nodes()
        rejected += list(mobile_rejections)
        bundle = {'base': base, 'nodes': nodes, 'metadata': metadata, 'sources': sources,
                  'historical_candidates': historical,
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
    elif args.phase not in ('repair', 'web-recheck', 'medium-recheck', 'stability-recheck'):
        records, endpoint_count = probe_pipeline(nodes, binary, root)
    if args.phase == 'medium-recheck':
        medium_rechecked_count = recheck_medium_download(records, mapping, binary, root)
    if args.phase == 'web-recheck':
        website_rechecked_count = recheck_websites(records, mapping, binary, root)
    reachable = [r for r in records if r['entry']['status'] == 'passed']
    if args.phase not in ('repair', 'web-recheck', 'medium-recheck', 'stability-recheck'):
        ip_types = s.lookup_ip_types(r['exit']['exit_ip'] for r in records if r['exit'])
        for record in records:
            record['sources'] = metadata.get(record['id'], {}).get('sources', [])
            record['candidate_origin'] = metadata.get(record['id'], {}).get('candidate_origin', 'latest_subscriptions')
            record['ip_type'] = ip_types.get((record.get('exit') or {}).get('exit_ip'), {'status': 'unknown', 'hosting': None})
    if args.phase not in ('repair', 'web-recheck', 'medium-recheck', 'stability-recheck') or args.refresh_ip_reputation:
        eligible_ips = [(r.get('exit') or {}).get('exit_ip') for r in records
                        if (r.get('download') or {}).get('status') == 'passed'
                        and r.get('exit_consistent') is not False]
        reputations = ip_reputation.lookup(eligible_ips, os.environ.get('IPAPI_IS_KEY', ''))
        for record in records:
            record['ip_reputation'] = reputations.get((record.get('exit') or {}).get('exit_ip'),
                {'status': 'unknown', 'provider': 'ipapi.is', 'reason': 'not_eligible'})
    stability_diagnostic = None
    if args.phase in ('all', 'publish', 'stability-recheck'):
        candidates = [r for r in records if r['id'] in mapping
            and r['entry']['status'] == 'passed'
            and (r.get('download') or {}).get('status') == 'passed'
            and (web_quality_eligible(r) or regional_eligible(r))]
        stability_diagnostic = stability.recheck(candidates, mapping, binary, root)
    config = render_comparison(base, records, mapping,
        require_stability=args.phase in ('all', 'publish', 'stability-recheck'))
    if args.phase in ('all', 'publish'):
        write_attempt(root, records, config, REQUIRED_SITES, sources, input_count,
                      s.datetime.now(s.TZ).isoformat(timespec='seconds'), required_traces=REQUIRED_TRACES)
    if not config['proxies']:
        if args.phase in ('all', 'publish'):
            print('全量检测完成：无符合页面、trace及应用TLS门槛的节点，报告已保存；原订阅未更新', flush=True)
            return
        raise RuntimeError('没有满足综合或台湾／新加坡门槛的节点；保留旧订阅')
    candidate = root / 'selected.yaml'; s.dump(candidate, config)
    checked = subprocess.run([binary, '-t', '-d', str(root), '-f', str(candidate)], capture_output=True, text=True, timeout=90)
    if checked.returncode:
        raise RuntimeError('最终订阅校验失败，不发布')
    now = s.datetime.now(s.TZ).isoformat(timespec='seconds')
    counts = {v: sum(r['entry']['status'] == v for r in records) for v in ('passed', 'failed', 'unknown')}
    repairing = args.phase in ('repair', 'web-recheck', 'medium-recheck', 'stability-recheck')
    published_names = {n['name'] for n in config['proxies']}
    published_ids = [r['id'] for r in records if r.get('name') in published_names and r['id'] in mapping]
    report = {'updated_at': now, 'scope': bundle['scope'], 'schema_version': 17,
              'historical_candidates': bundle.get('historical_candidates', {}),
              'stability_policy': stability.settings(),
              'stability_recheck': ({'updated_at': stability_diagnostic['updated_at'],
                  'node_count': stability_diagnostic['node_count'], 'controls_valid': stability_diagnostic['controls_valid'],
                  'scope': 'eligible_pool_after_downloads',
                  'passed_count': sum(stability.passed(r.get('stability')) for r in records),
                  'quality_eligible_count': sum(stability.passed(r.get('stability')) and (web_quality_eligible(r) or regional_eligible(r)) for r in records),
                  'failed_count': sum((r.get('stability') or {}).get('status') == 'failed' for r in records)}
                  if stability_diagnostic and stability_diagnostic['node_count'] else previous.get('stability_recheck') if repairing else None),
              'app_tls_policy': {'version': app_tls.VERSION, 'targets': list(app_tls.TARGETS),
                  'rounds_per_target': app_tls.ROUNDS, 'budget_seconds_per_handshake': app_tls.BUDGET_SECONDS,
                  'requires_trusted_chain_hostname_validity': True, 'android_certificate_pinning_emulated': False},
              'app_tls_counts': {v: sum((r.get('app_tls') or {}).get('status') == v for r in records)
                                 for v in ('passed', 'failed', 'skipped')},
              'measurements_updated_at': bundle.get('measurements_updated_at', now),
              'publication_mode': args.phase if repairing else 'full',
              'website_recheck': ({'updated_at': now, 'node_count': website_rechecked_count,
                  'scope': 'available_published_quick_download_passed', 'overseas_rounds': WEBSITE_ROUNDS,
                  'workers': 8, 'jobs': 1,
                  'preserved_measurements': ['HTTPS204', 'domestic_TCP', 'domestic_pages', 'trace', '1MB_download', 'high_speed_download']}
                  if args.phase == 'web-recheck' else previous.get('website_recheck') if repairing else None),
              'cloudflare_classification_update': ({'updated_at': now, 'reclassified_attempts': reclassified_count,
                  'new_measurements': False, 'source': 'captured_cloudflare_challenge_restriction'}
                  if repairing else None),
              'website_measurement_policy': {'version': 5,
                  'confirmed_cloudflare_challenge': 'accepted_access_verification_required',
                  'challenge_in_page_speed_ranking': False,
                  'challenge_can_replace_204_or_trace': False, 'overseas_rounds': WEBSITE_ROUNDS,
                  'domestic_and_trace_rounds': 1, 'sample_bytes': 16384,
                  'sample_bytes_overrides': PAGE_SAMPLE_LIMITS,
                  'max_ttfb_ms': MAX_TTFB_MS, 'max_sample_ms': MAX_SAMPLE_MS,
                  'required_core_sites': list(CORE_SITES), 'required_websites': list(REQUIRED_SITES),
                  'required_websites_rounds': WEBSITE_ROUNDS, 'trace_can_replace_required_page': False,
                  'required_traces': list(REQUIRED_TRACES), 'required_trace_rounds': 1,
                  'claude_validation': 'trace_only', 'claude_homepage_tested': False,
                  'core_median_limit_ms': CORE_MEDIAN_MS,
                  'core_p95_limit_ms': CORE_TAIL_MS, 'core_jitter_limit_ms': CORE_JITTER_MS,
                  'min_accepted_overseas_sites': math.ceil(len(OVERSEAS_SITES) / 2),
                  'eligible_count': sum(web_quality_eligible(r) and (r.get('download') or {}).get('status') == 'passed' for r in records)},
              'mobile_rejections': bundle.get('mobile_rejections', {}),
              'pipeline': True, 'parallel_shards': bundle.get('parallel_shards', args.shard_count if args.phase == 'publish' else 1),
              'website_workers_per_shard': 16,
              'parallel_sites_per_node': previous.get('parallel_sites_per_node', 3) if repairing else SITE_WORKERS,
              'test_targets': previous.get('test_targets', {k: SITES[k] for k in PAGE_SITES}) if repairing else dict(SITES),
              'target_categories': previous.get('target_categories', {'overseas': list((previous.get('test_targets') or {})), 'domestic': []}) if repairing else {'overseas': list(OVERSEAS_SITES), 'domestic': list(DOMESTIC_SITES), 'connectivity': list(CONNECTIVITY_SITES)},
              'routing_policy': {'domestic': 'DIRECT', 'overseas': '🚀 全局选择', 'unmatched': '🚀 全局选择', 'group_count': len(config['proxy-groups']), 'version': 2},
              'stages': previous.get('stages', ['TCP', 'websites']) if repairing else ['HTTPS204', 'domestic_TCP', 'websites_and_trace', 'application_TLS', 'quick_download', '5MB_quick_download', '100MB_Cloudflare_download', '100MB_DataPacket_download', 'time_spaced_stability'],
              'precheck_rounds': previous.get('precheck_rounds', 0) if repairing else 3,
              'website_rounds': WEBSITE_ROUNDS if args.phase == 'web-recheck' or not repairing else previous.get('website_rounds', 1),
              'trace_rounds': previous.get('trace_rounds', 1) if repairing else 1,
              'download_test': previous.get('download_test', False) if repairing else True,
              'download_settings': previous.get('download_settings') if repairing else {'url': DOWNLOAD_URL, 'bytes': DOWNLOAD_BYTES, 'budget_seconds': DOWNLOAD_BUDGET, 'rounds': 1, 'read_timeout_seconds': 1, 'includes_handshake': True},
              'web_user_agent': previous.get('web_user_agent') if repairing else WEB_USER_AGENT,
              'medium_speed_download_settings': medium_speed.settings(),
              'medium_speed_download_counts': medium_speed.counts(records),
              'medium_speed_selection_policy': {'group': medium_speed.GROUP, 'requires_5mb_pass': True,
                  'requires_published_eligible_pool': True, 'regional_exception_allowed': True, 'hong_kong_limit': 30, 'other_regions_limit': None,
                  'selected_count': sum(n != 'REJECT' for g in config['proxy-groups'] if g['name'] == medium_speed.GROUP for n in g['proxies'])},
              'medium_speed_recheck': ({'updated_at': now, 'node_count': medium_rechecked_count,
                  'scope': 'published_1mb_passed', 'preserved_measurements': ['204', 'TCP', 'websites', 'app_TLS', '1MB', '100MB_double']}
                  if args.phase == 'medium-recheck' else previous.get('medium_speed_recheck') if repairing else None),
              'high_speed_download_test': previous.get('high_speed_download_test', False) if repairing else True,
              'high_speed_download_settings': ({**previous['high_speed_download_settings'], 'selection_limit': None}
                  if previous.get('high_speed_download_settings') else None) if repairing else high_speed.settings(),
              'node_selection_policy': {'hong_kong_limit_per_group': 30, 'other_regions_limit': None,
                  'non_datacenter_total_limit': None, 'qualified_pool_only': True,
                  'requires_time_spaced_stability': args.phase in ('all', 'publish', 'stability-recheck') or bool(previous.get('node_selection_policy', {}).get('requires_time_spaced_stability')) if repairing else True,
                  'requires_domestic_tcp_pass': True, 'requires_application_tls_pass': True,
                  'rejected_proxy_definitions': 'omitted',
                  'regional_exception': {'group': REGIONAL_GROUP, 'country_codes': list(REGIONAL_COUNTRIES),
                      'median_limit_ms': REGIONAL_MEDIAN_MS, 'tail_limit_ms': REGIONAL_TAIL_MS,
                      'jitter_limit_ms': REGIONAL_JITTER_MS, 'required_core_rounds': WEBSITE_ROUNDS,
                      'requires_204_rounds': 3, 'requires_quick_download': True,
                      'requires_overseas_coverage': False, 'exit_conflict_allowed': False,
                      'other_groups_use_strict_pool': True, 'required_websites': list(REQUIRED_SITES), 'required_traces': list(REQUIRED_TRACES)}},
              'regional_selection': {'group': REGIONAL_GROUP,
                  'selected_count': sum(regional_eligible(r) and r['id'] in published_ids for r in records),
                  'country_counts': {cc: sum(r['id'] in published_ids and regional_eligible(r)
                      and (r.get('exit') or {}).get('country_code') == cc for r in records)
                      for cc in REGIONAL_COUNTRIES}},
              'published_node_count': len(config['proxies']), 'published_node_ids': published_ids,
              'node_naming_policy': {'format': '地区编号|延迟ms|带宽Mbps|住宅类型|纯净度百分比',
                  'numbering': 'ranked_per_region_starting_01', 'speed_source_priority': ['100MB_double_minimum', '5MB', '1MB'],
                  'residential_label': 'ipapi_isp_and_not_datacenter', 'unknown_fields_remain_unknown': True},
              'ip_reputation_policy': {'provider': 'ipapi.is', 'scope': 'quick_download_passed_unique_exits',
                  'configured': bool(os.environ.get('IPAPI_IS_KEY')), 'lookup_budget_per_run': ip_reputation.DAILY_LOOKUP_BUDGET,
                  'purity_formula': '100 * (1 - company.abuser_score_numeric_ratio)', 'score_scope': 'company_network_not_individual_ip',
                  'confirmed_nodes': sum((r.get('ip_reputation') or {}).get('status') == 'success' for r in records)},
              'high_speed_selection_policy': {'max_elapsed_seconds': HIGH_DOWNLOAD_BUDGET, 'selection_limit': None,
                                              'required_urls': list(high_speed.URLS), 'required_bytes_per_round': HIGH_DOWNLOAD_BYTES,
                                              'required_rounds': len(high_speed.URLS), 'speed_aggregation': 'minimum_of_completed_rounds',
                                              'selected_count': sum(n != 'REJECT' for g in config['proxy-groups'] if g['name'] == '⚡ 高速下载' for n in g['proxies'])},
              'high_speed_download_counts': high_speed.result_counts(records),
              'high_speed_target_counts': {url: high_speed.status_counts(records, i) for i, url in enumerate(high_speed.URLS)},
              'input_unique_count': input_count, 'parseable_count': bundle.get('parseable_count', len(nodes)), 'invalid_node_ids': rejected,
              'unique_tcp_endpoints': endpoint_count,
              'total_unique_tcp_endpoints': bundle.get('total_unique_tcp_endpoints',
                  len({endpoint_key(n) for n in nodes if tcp_supported(n)})),
              'precheck_counts': {v: sum((r.get('precheck') or {}).get('status') == v for r in records)
                                  for v in ('passed', 'failed', 'unstable', 'needs_review')},
              'entry_counts': counts, 'website_tested_count': len(reachable),
              'website_target_count': sum(label in (previous.get('test_targets') or {}) for label in PAGE_SITES) if repairing else len(PAGE_SITES),
              'overseas_target_count': sum(label in (previous.get('test_targets') or {}) for label in OVERSEAS_SITES) if repairing else len(OVERSEAS_SITES),
              'domestic_target_count': sum(label in (previous.get('test_targets') or {}) for label in DOMESTIC_SITES) if repairing else len(DOMESTIC_SITES),
              'all_websites_passed': sum(all((r.get('websites') or {}).get(label, {}).get('status') == 'passed' for label in OVERSEAS_SITES) for r in records),
              'three_connectivity_passed': sum(connectivity_count(r) == 3 for r in records),
              'download_counts': {v: sum((r.get('download') or {}).get('status') == v for r in records)
                                  for v in ('passed', 'failed', 'skipped')},
              'services': services, 'sources': sources, 'nodes': records}
    Path('优选配置.yaml').write_text(f'# 分阶段检测；{now}；检测轮数和下载设置见连通性报告\n' + candidate.read_text())
    Path('连通性报告.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    rows = ['# 节点分阶段连通性与快速下载', '', f'发布时间：{now}；检测数据时间：{report["measurements_updated_at"]}', '',
            f'去重节点 {input_count}；内核可解析 {report["parseable_count"]}；实际发布 {report["published_node_count"]}；TCP 入口总数 {report["total_unique_tcp_endpoints"]}，原检测提交 {endpoint_count}。', '',
            f'204 全通过 {report["precheck_counts"]["passed"]}；TCP 通 {counts["passed"]}，不通 {counts["failed"]}，未验证 {counts["unknown"]}；海外访问检测 {len(reachable)}；1MB 快测通过 {report["download_counts"]["passed"]}；100MB双轮完整下载通过 {report["high_speed_download_counts"]["passed"]}。', '',
            f'检测顺序：{" → ".join(report["stages"])}。204 {report["precheck_rounds"]} 轮；海外网站 {report["website_rounds"]} 轮；国内及 trace 各 {report["trace_rounds"]} 轮；下载检测 {"开启" if report["download_test"] else "关闭"}。兼容性修复保留原检测数据，未测项目保持未测。', '',
            '204 三轮均返回 HTTPS 204 且无正文才进入 TCP；204 未通过的节点延迟显示未知，分类及跳过原因保留在 JSON 报告，不伪造国内入口不通。UDP 的 TCP 阶段不适用，保持未验证。', '',
            'TCP 来自小小 API 的国内探测点，运营商未公开，不代表移动或手机本地必然可用。共享主机和端口只提交一次，不同凭据分别检查 204 和海外访问。接口限流、超时、异常和目标不匹配均记为未验证。', '',
            f'本轮 {report["parallel_shards"]} 个并行 Actions 分片，每片最多同时检测 16 个节点。同一节点按顺序过关，不同节点可同时处于不同阶段；海外网页各请求三轮，国内及 trace 各一次，每节点最多五个请求并发；新增网站不会增加并发连接上限。', '',
            '海外网页目标：' + '、'.join(OVERSEAS_SITES) + '；另测 ChatGPT、Claude 两个 trace。', '',
            '国内网页目标：' + '、'.join(DOMESTIC_SITES) + '。这些检测由 GitHub 通过当前节点访问国内站点，仅供出口回国访问对照；手机规则将国内站点直连，因此不代表手机直连、移动线路延迟或地区解锁。国内结果不参与海外排名，也不能单独触发下载阶段。', '',
            '网页Amazon最多读取64 KB，其余最多16 KB，分别记录响应头与样本接收耗时、字节数。响应头>3000ms或样本>5000ms记为响应慢；明确cf-mitigated: challenge且来自预期HTTPS网站的验证页单列CF需验证，认可网站可达，不记访问失败；普通403、其他验证码或风控仍需复核。CF验证响应不作为真实页面速度，不替代204、trace或应用TLS。trace 必须返回预期域名、公网出口 IP、地区和 HTTPS 标识，只表示域名连通，不证明登录、对话或视频播放可用。', '',
            'TCP通且指定12个海外网站各三轮均正常响应或明确CF验证且Claude trace单轮通过后，使用 Cloudflare 官方 __down?bytes=1000000 下载 1 MB 一次，读取超时 1 秒、采样预算 6 秒；完整长度、类型和响应状态匹配才通过。到预算即停止读取，单次底层连接/读取可能再等待其自身超时。速度包含 TLS 和首字节等待，是小文件快速采样速度，不能代表峰值带宽。', '',
            f'1 MB通过后增加Cloudflare 5 MB快测（{medium_speed.URL}），完整5,000,000字节、{medium_speed.BUDGET}秒内完成，每分片最多{medium_speed.WORKERS}节点并发。中速组保留已入选合格池中全部真实5 MB通过节点（含仅符合台湾／新加坡较宽网页门槛者）；不补用1 MB或100 MB成绩。5 MB失败不取消其他组资格或后续100 MB测试；香港最多30个、其他地区不限。中速组本次{report["medium_speed_selection_policy"]["selected_count"]}个。', '',
            f'仅1 MB快测通过的节点继续依次测试Cloudflare（{high_speed.URLS[0]}）和DataPacket（{high_speed.URLS[1]}），每次完整100,000,000字节、各自{HIGH_DOWNLOAD_BUDGET}秒，读取超时1秒，每分片最多同时测试2个节点。两次都通过才进入高速组，按较慢一次速度排序和命名；历史单轮结果不冒充双轮通过。本批数据的实际设置：{report["high_speed_download_settings"]}；重建配置不改写历史采样。香港最多30个，其他地区不限，本次高速组{report["high_speed_selection_policy"]["selected_count"]}个。未通过1 MB的节点不消耗大文件流量。', '',
            f'逐目标100 MB结果：{report["high_speed_target_counts"]}。', '',
            '综合优选要求1 MB通过、指定12个海外网站各三轮均正常响应或明确CF验证且Claude trace单轮通过；Google/YouTube三轮真实页面、中位耗时≤1500ms、最慢一轮≤3000ms、极差≤1500ms；必过网站不由其他站或trace替代；按网站尾延迟、中位耗时和波动优先排序，再比较覆盖与下载。不用下载速度掩盖网页响应差。综合、高速和非机房组仅香港最多 30 个，其他地区不限数量。非机房组仍按出口 IP 去重，且必须明确 hosting=false。', '',
            '手机显示六个分组：全局选择、综合优选、中速下载、高速下载、非机房 IP、台湾／新加坡。综合、高速和非机房组共用严格合格池；地区组使用用户授权的较宽响应门槛；中速组接受两类合格池中5 MB通过者；不满足任何入选门槛的节点定义和凭据不写入订阅，记录保留在报告。每天重新获取全部来源，可让恢复的节点重新入选。网站延迟及速度来自 GitHub 云端，国内 TCP 分类已由用户本地对照。', '',
            f'台湾／新加坡按已确认出口地区入选，不按来源名称猜测：204三轮、国内TCP、1 MB下载、指定12站各三轮正常响应或明确CF验证，Claude trace单轮须通过；核心网页中位耗时≤{REGIONAL_MEDIAN_MS}ms、最慢≤{REGIONAL_TAIL_MS}ms、极差≤{REGIONAL_JITTER_MS}ms。12个指定页面必过（明确CF验证认可可达），Claude仅检测trace；不允许其他页面或trace替代12站，其他验证码、错误页面或未测项目不放行。Google/YouTube响应质量仍要求三轮真实页面，验证页速度不参与质量判定。仅满足地区门槛的节点进入地区组，5 MB通过时也进入中速组，不进入综合、高速或非机房组。本次地区数量：{report["regional_selection"]["country_counts"]}。无节点则显示REJECT，不补入失败节点。', '',
            '节点名称：美国01|120ms|85Mbps|住宅/非住宅|纯净度99.2%。每地区独立从01顺序编号，不加空格或节点哈希。延迟取Google/YouTube真实页面较慢的中位数，缺失时采用204中位数；带宽优先双100 MB较慢速度，其次5 MB、最后1 MB；住宅依据ipapi.is的ISP且非机房分类，表示网络类型判断，不保证独享静态家庭IP；机房/移动网络标非住宅，只有hosting=false时仍标住宅未知。缺少信誉数据标纯净度未知，已知滥用详情保留JSON。非机房不能直接等同住宅。纯净度 = 100 × (1 − ipapi.is company.abuser_score 的数值比例)，是网段未标记滥用比例，不是单个 IP 的综合风控分。缺少数据显示未知，已知滥用单独标注。', '',
            '分流：局域网直连，保留广告拦截；明确的海外 AI、社交、影音、开发服务及相关资源域名优先走全局选择，国内站点直连，随后保留个人域名例外与维护中的规则集，未匹配流量走全局选择。Cursor 改走代理，移除 Tencent/元宝关键词直连，补上 GFW 规则；不增加应用策略组。节点域名和国内 DNS 用国内解析器，海外 DNS 随全局选择走代理，移除绑定旧局域网的引导 DNS。', '',
            '## 服务状态', '', '| 服务 | 当前接入 | 状态说明 |', '|---|---|---|']
    for name, service in services.items():
        rows.append(f'| [{name}]({service["url"]}) | {service["mode"]} | {service.get("reason", "公开 TCPing API，最多 5 次请求/秒")} |')
    rows += ['', '表格仅展示进入海外网站检测的节点；全部节点及跳过原因见 [JSON 完整报告](连通性报告.json)。', '']
    if repairing:
        rows += ['', f'本次按新策略重新分类{reclassified_count}次已记录的明确CF验证响应；保留原HTTP状态、采样耗时和测量时间，没有重新测速。', '']
    rows += ['## 网站覆盖', '', '| 网站 | 分类 | 通过 | 不通过 | 响应慢 | 波动 | CF需验证 | 需复核 | 未测 |', '|---|---|---:|---:|---:|---:|---:|---:|---:|']
    for label, url in report['test_targets'].items():
        if label == 'Google204':
            continue
        measured = [(record.get('websites') or {}).get(label) for record in reachable]
        tallies = {status: sum(item is not None and item['status'] == status for item in measured)
                   for status in ('passed', 'failed', 'slow', 'unstable', 'verification_required', 'needs_review')}
        kind = '国内（经节点）' if label in DOMESTIC_SITES else 'trace' if label in CONNECTIVITY_SITES else '海外'
        rows.append(f'| [{label}]({url}) | {kind} | {tallies["passed"]} | {tallies["failed"]} | {tallies["slow"]} | {tallies["unstable"]} | {tallies["verification_required"]} | {tallies["needs_review"]} | {sum(item is None for item in measured)} |')
    medium_rechecked = report.get('medium_speed_recheck')
    if medium_rechecked:
        rows += ['', f'5 MB专项补测：{medium_rechecked["updated_at"]}；{medium_rechecked["node_count"]}个已发布1 MB通过节点，4节点并发。5 MB采样时间单独记录，204、TCP、网站、TLS、1 MB和100 MB双轮保留原测量时间。', '']
    rechecked = report.get('website_recheck')
    if rechecked:
        rows += ['', f'海外网站专项复测：{rechecked["updated_at"]}；{rechecked["node_count"]} 个旧下载通过节点，单作业8节点并发。未复测的旧网站结果保持原轮数；TCP、204、下载、国内网页和trace仍使用原测量时间。', '']
    rows += ['', '## 请求响应质量', '', '下表仅展示海外三轮数据。P95为三次测量的最大值，波动为极差；响应头耗时为近似首字节时间，含建连和跳转。', '',
        '| 节点 | 综合合格 | 海外稳定站 | Google 成功/中位/P95 | YouTube 成功/中位/P95/波动/响应头 |', '|---|---|---:|---|---|']
    for record in records:
        results = record.get('websites') or {}
        yt = results.get('YouTube') or {}; google = results.get('Google') or {}
        if yt.get('round_count') != WEBSITE_ROUNDS:
            continue
        def timing(item):
            return f'{item.get("passed_count", 0)}/{item.get("round_count", 0)}，{item.get("median_elapsed_ms")} / {item.get("p95_elapsed_ms")}ms'
        rows.append(f'| {record["id"][2:]} | {"是" if web_quality_eligible(record) else "否"} | {website_count(record)} | {timing(google)} | {timing(yt)}，极差{yt.get("jitter_ms")}ms，响应头{yt.get("median_ttfb_ms")}ms |')
    rows += ['', '## 手机对照', '', '刷新原订阅，进入“🚀 全局选择”，优先选择“⭐ 综合优选”；TCP 分类与 204 失败原因在下表及 JSON 报告查看。下表列出完整节点名称与报告编号的对应关系。反馈完整节点名称和手机实际体验。', '',
             '| 节点名 | 编号 | 入口 | TCP 分类 | 地区 | HTTPS204（三轮） | 海外通过 | 国内通过（经节点） | ChatGPTTrace | ClaudeTrace | 1MB快测 | 5MB快测 | 100MB双轮下载 |',
             '|' + '---|' * 13]
    for record in records:
        if not record.get('websites'):
            continue
        results = record['websites']
        scores = []
        for item in [record.get('precheck')]:
            score = f'{item["passed_count"]}/{item["round_count"]} {LABELS[item["status"]]}' if item else '未测'
            if item and item.get('median_elapsed_ms') is not None:
                score += f'，中位 {item["median_elapsed_ms"]}ms / 最大 {item.get("max_elapsed_ms", "未记录")}ms'
            scores.append(score)
        scores += [f'{website_count(record)}/{sum(label in results for label in OVERSEAS_SITES)}',
                   f'{domestic_count(record)}/{sum(label in results for label in DOMESTIC_SITES)}']
        scores += [LABELS.get((results.get(label) or {}).get('status'), '未测') for label in ('ChatGPTTrace', 'ClaudeTrace')]
        downloaded = record.get('download') or {}
        scores.append(f'{downloaded["speed_mib_s"]:.3f} MiB/s' if downloaded.get('status') == 'passed' else LABELS.get(downloaded.get('status'), '未测'))
        medium = record.get('medium_speed_download') or {}
        scores.append(f'{medium["speed_mib_s"]:.3f} MiB/s' if medium_speed.passed(medium) else LABELS.get(medium.get('status'), '未测'))
        high = record.get('high_speed_download') or {}
        scores.append(f'{high["speed_mib_s"]:.3f} MiB/s' if high_speed.passed(high) else
                      '旧样本未验证双轮' if high.get('status') == 'passed' else LABELS.get(high.get('status'), '未测'))
        country = (record.get('exit') or {}).get('country_code')
        display_name = record.get('name', '未入选').replace('|', '\\|')
        rows.append(f'| {display_name} | {record["id"][2:]} | {record["server"]}:{record["port"]} | {LABELS[record["entry"]["status"]]} | {s.COUNTRIES.get(country, country) or "未确认"} | ' + ' | '.join(scores) + ' |')
    if rejected:
        rows += ['', '内核或手机兼容性校验未通过的节点未写入订阅，编号：' + '、'.join(rejected)]
    temporal = report.get('stability_recheck')
    if temporal:
        rows[6:6] = [f'间隔稳定性复测：{temporal["updated_at"]}；检测{temporal["node_count"]}，通过{temporal["passed_count"]}，未通过{temporal["failed_count"]}。5轮各检查204、Google、YouTube、ChatGPT trace和Android域名证书握手；轮间至少空闲30秒，4节点并发，每节点串行请求。5轮全部通过才发布，出口IP变化不淘汰，所有分组仍手动选择。这是数分钟的云端观察，不证明手机移动/Wi-Fi或登录后的ChatGPT持续对话可用。原始下载及网页时间保持原样。', '']
    Path('连通性报告.md').write_text('\n'.join(rows) + '\n')
    print(f'分阶段分类完成，配置校验通过；204 {report["precheck_counts"]}；TCP {counts}；下载 {report["download_counts"]}', flush=True)


if __name__ == '__main__':
    main()
