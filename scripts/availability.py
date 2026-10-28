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
import chain_fronts
import ip_reputation
import app_tls
import published_history
import high_speed
import medium_speed
import stability
import continuous_stability
import upload_speed
import service_probes
import quality_policy as qp
import quality_history
import transfer_probe
import application_quality
import edge_candidates
from v2rayn_subscription import render_with_skips as render_v2rayn
from untested_subscription import append_from_env as append_untested
from bandwidth_gate import BandwidthGate
from detection_report import write_report, website_access_summary, latest_cohort
from attempt_report import write_attempt
from mobile_pilot import MAX_TTFB_MS, MAX_SAMPLE_MS, CLOUDFLARE_204_URL, PAGE_SAMPLE_LIMITS, REDDIT_LOGIN_SAMPLE_BYTES, confirmed_cloudflare_challenge, confirmed_reddit_login, confirmed_page_exception

XXAPI = 'https://v2.xxapi.cn/api/tcping'
LABELS = {'passed': '通', 'failed': '不通', 'unknown': '未验证',
          'unstable': '波动', 'verification_required': 'CF需验证', 'login_required': '登录提示通过', 'needs_review': '需人工复核', 'skipped': '未测', 'slow': '响应慢'}
WEBSITE_ROUNDS = 3
CORE_SITES = ('Google', 'YouTube')
REQUIRED_SITES = ('Google', 'YouTube', 'ChatGPT', 'Gemini', 'GitHub',
                  'Wikipedia', 'Reddit', 'X', 'Instagram', 'Telegram', 'Discord', 'Facebook', 'ChatGPTAPI')
REQUIRED_TRACES = ('ClaudeTrace',)
CORE_MEDIAN_MS = 1500
CORE_TAIL_MS = 3000
CORE_JITTER_MS = 1500
REGIONAL_GROUP = '🌏 台湾／新加坡'
REGIONAL_COUNTRIES = ('TW', 'SG')
REGIONAL_MEDIAN_MS = 3000
REGIONAL_TAIL_MS = 5000
REGIONAL_JITTER_MS = 3000
# Group health checks target Claude: every published node already passed this trace once,
# and it reflects the service the user actually needs. url-test expects HTTP 200, not 204.
GROUP_TEST_URL = SITES['ClaudeTrace']
GROUP_TEST_STATUS = 200
# Domestic apps use DIRECT: keep their routing catalog, but avoid measuring
# unrelated return-to-China pages through every overseas proxy each day.
DAILY_POST_SITES = {label: url for label, url in POST_SITES.items() if label not in DOMESTIC_SITES}
DAILY_SITES = {'Google204': SITES['Google204'], **DAILY_POST_SITES}


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


PRECHECK_URLS = {'Google204': SITES['Google204'], 'Cloudflare204': CLOUDFLARE_204_URL}


def combine_204(targets):
    rounds = []
    for index in range(3):
        g, c = (targets[label]['attempts'][index] for label in PRECHECK_URLS)
        item = copy.deepcopy(g)  # Preserve Google latency naming, not the sum of two requests.
        if g['status'] != 'passed' or c['status'] != 'passed':
            item.update(status='failed', reason='；'.join(
                label + '：' + str(sample.get('reason') or sample.get('error_type') or sample['status'])
                for label, sample in (('Google204', g), ('Cloudflare204', c)) if sample['status'] != 'passed'))
        rounds.append({'Google204': item})
    combined = summarize_rounds(rounds, ('Google204',))['Google204']
    combined.update(version=2, targets=targets)
    return combined


def precheck_204(port):
    rounds = []
    for index in range(3):
        order = list(PRECHECK_URLS) if index % 2 == 0 else list(reversed(PRECHECK_URLS))
        rounds.append({label: check_site(port, label, PRECHECK_URLS[label], timeout=(2, 3)) for label in order})
    return combine_204(summarize_rounds(rounds, tuple(PRECHECK_URLS)))


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
                            verify=True,
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
                   site_check=None, download=quick_download, large_download=high_speed_download, interval=.25, workers=16,
                   medium_download=None, upload_precheck=None, upload_controls=None,
                   preflight_only=False, initial_records=None, service_check=None, policy_version=None):
    """Per-node stages are ordered, while different nodes overlap across stages."""
    medium_download = medium_download or medium_speed_download
    modern = policy_version == qp.VERSION
    if modern:
        if download is quick_download:
            download = lambda port: transfer_probe.download(port, DOWNLOAD_BYTES, DOWNLOAD_BUDGET)
        if medium_download is medium_speed_download:
            medium_download = lambda port: transfer_probe.download(port, medium_speed.BYTES, medium_speed.BUDGET)
        if large_download is high_speed_download:
            large_download = lambda port: high_speed.summarize([
                transfer_probe.download(port, high_speed.BYTES, high_speed.BUDGET, url) for url in high_speed.URLS])
    upload_precheck = upload_precheck or (lambda port: upload_speed.sample(
        port, upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET, root))
    controls = upload_controls if upload_controls is not None else {}
    if initial_records is None or modern:
        controls.update(before=None, after=None, valid=None, node_count=0)
    if not nodes:
        controls['valid'] = True
        return [], 0
    site_check_is_default = site_check is None
    site_check = site_check or (lambda port: check_sites(port, DAILY_POST_SITES))
    seed = {r['id']: r for r in initial_records or []}
    if initial_records is not None and set(seed) != {n['name'] for n in nodes}:
        raise ValueError('前置记录存在缺失或多余节点')
    active = [n for n in nodes if initial_records is None or
              (seed[n['name']]['entry']['status'] == 'passed' and (modern or upload_speed.sample_passed(
                  seed[n['name']].get('upload_precheck') or {}, upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET)))]
    initial_endpoint_count = len({endpoint_key(n) for n in nodes if tcp_supported(n)
        and seed[n['name']]['precheck']['status'] == 'passed'}) if initial_records is not None else None
    if not active:
        controls['valid'] = True
        return copy.deepcopy(initial_records), initial_endpoint_count
    listeners, ports = s.make_listeners({'id': n['name']} for n in active)
    pace, lock, tcp_jobs = Pace(interval), threading.Lock(), {}
    medium_slots = threading.BoundedSemaphore(medium_speed.WORKERS)
    large_slots = threading.BoundedSemaphore(HIGH_DOWNLOAD_WORKERS)
    bandwidth = BandwidthGate()
    abort = threading.Event()
    progress = {'done': 0, 'precheck': 0, 'tcp': 0, 'upload_precheck': 0,
                'websites': 0, 'download': 0, 'medium_speed': 0, 'high_speed': 0}
    with s.Core(binary, root, active, listeners), futures.ThreadPoolExecutor(max_workers=10) as tcp_pool:
        def measure(node):
            if abort.is_set():
                raise RuntimeError('上行预检对照异常，停止本分片')
            port = ports.get(node['name'])
            record = {'id': node['name'], 'server': node['server'], 'port': node['port'], 'protocol': node['type'],
                      'entry': {'status': 'unknown', 'attempts': 0, 'reason': '204 未通过，未提交国内 TCP 检测'},
                      'upload_precheck': {'status': 'skipped', 'reason': '国内TCP未通过，未提交上行预检'},
                      'websites': None, 'exit': None, 'download': {'status': 'skipped', 'reason': '未进入下载阶段'},
                      'app_tls': {'status': 'skipped', 'reason': '必过网站未通过，未提交应用TLS检查'},
                      'medium_speed_download': {'status': 'skipped', 'reason': '1 MB快测未通过，未提交5 MB测试'},
                      'high_speed_download': {'status': 'skipped', 'reason': '1 MB 快测未通过，未提交两轮100 MB测试'}}
            if initial_records is not None:
                record = copy.deepcopy(seed[node['name']])
            else:
                record['precheck'] = precheck(port)
            if modern:
                record['selection_policy_version'] = qp.VERSION
            if initial_records is None and record['precheck']['status'] == 'passed':
                if not tcp_supported(node):
                    record['entry']['reason'] = 'UDP 协议不适用 TCP 检测，后续阶段未测'
                else:
                    key = endpoint_key(node)
                    with lock:
                        if key not in tcp_jobs:
                            tcp_jobs[key] = tcp_pool.submit(probe, key, pace)
                        job = tcp_jobs[key]
                    record['entry'] = copy.deepcopy(job.result())
                if record['entry']['status'] == 'passed' and not modern:
                    with bandwidth.upload():
                        if controls['before'] is None:
                            controls['before'] = upload_precheck(None)
                        if not upload_speed.sample_passed(controls['before'], upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET):
                            controls['valid'] = False
                            abort.set()
                            raise RuntimeError('上行预检直连对照异常，不据此淘汰或发布')
                        record['upload_precheck'] = upload_precheck(port)
                        record['upload_precheck_updated_at'] = s.datetime.now(s.TZ).isoformat(timespec='seconds')
                        controls['node_count'] += 1
                    if not upload_speed.sample_passed(record['upload_precheck'], upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET):
                        record['download']['reason'] = 'TCP通过但3MB上行预检未通过，跳过网站和下载'
            if not preflight_only:
                if modern and record['entry']['status'] == 'passed':
                    with bandwidth.upload():
                        if controls['before'] is None:
                            controls['before'] = upload_precheck(None)
                        if not upload_speed.sample_passed(controls['before'], upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET):
                            raise RuntimeError('上行测量环境对照异常，保留原订阅')
                        record['upload_precheck'] = upload_precheck(port)
                        record['upload_precheck_updated_at'] = s.datetime.now(s.TZ).isoformat(timespec='seconds')
                        controls['node_count'] += 1
                if record['entry']['status'] == 'passed' and (modern or upload_speed.sample_passed(
                        record['upload_precheck'], upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET)):
                    rounds = [site_check(port)]
                    # Only traces get one round; overseas pages get three.
                    for _ in range(WEBSITE_ROUNDS - 1):
                        rounds.append(check_sites(port, {label: SITES[label] for label in OVERSEAS_SITES})
                            if site_check_is_default else site_check(port))
                    record['websites'] = summarize_rounds(rounds, labels=OVERSEAS_SITES)
                    record['websites'].update(summarize_rounds(rounds[:1],
                        labels=[label for label in DAILY_POST_SITES if label not in OVERSEAS_SITES]))
                    if modern:
                        for label in ('ChatGPTTrace', 'ClaudeTrace'):
                            item = record['websites'].get(label) or {}
                            if qp.transient((item.get('attempts') or [{}])[0]):
                                attempts = item['attempts'] + [check_site(port, label, SITES[label])]
                                record['websites'][label] = summarize_rounds([{label: a} for a in attempts], (label,))[label]
                    tls_sites = website_tls_failures(record)
                    record['website_tls'] = {'status': 'failed' if tls_sites else 'passed',
                        'sites': tls_sites, 'reason': '网站TLS异常：' + '、'.join(tls_sites) if tls_sites else '网站测试未出现TLS异常'}
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
                    if required_websites_passed(record) and not pre_application_tls_failure(record):
                        record['app_tls'] = app_tls.check(port, **({'retry_transient': True} if modern else {}))
                        if app_tls.passed(record['app_tls']):
                            if modern:
                                record['application_quality'] = application_quality.check(port)
                            with bandwidth.download():
                                record['download'] = download(port)
                            if record['download']['status'] == 'passed':
                                if service_check is not None:
                                    record['service_checks'] = service_check(port, bandwidth)
                                with medium_slots:
                                    with bandwidth.download():
                                        record['medium_speed_download'] = medium_download(port)
                                record['medium_speed_updated_at'] = s.datetime.now(s.TZ).isoformat(timespec='seconds')
                                with large_slots:
                                    with bandwidth.download():
                                        record['high_speed_download'] = large_download(port)
                        else:
                            record['download']['reason'] = 'ChatGPT应用TLS校验未全部通过，跳过下载'
                    else:
                        record['download']['reason'] = '网站TLS异常或必过网页/API/trace未通过，跳过下载'
            with lock:
                progress['done'] += 1
                progress['precheck'] += record['precheck']['status'] == 'passed'
                progress['tcp'] += record['entry']['status'] == 'passed'
                progress['upload_precheck'] += upload_speed.sample_passed(record['upload_precheck'], upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET)
                progress['websites'] += record['websites'] is not None
                progress['download'] += record['download']['status'] == 'passed'
                progress['medium_speed'] += medium_speed.passed(record['medium_speed_download'])
                progress['high_speed'] += record['high_speed_download']['status'] == 'passed'
                if progress['done'] % 100 == 0 or progress['done'] == len(nodes):
                    print(f'分阶段流水线 {progress["done"]}/{len(nodes)}：204通过 {progress["precheck"]}，TCP通过 {progress["tcp"]}，上行预检通过 {progress["upload_precheck"]}，网站完成 {progress["websites"]}，1MB下载通过 {progress["download"]}，5MB通过 {progress["medium_speed"]}，100MB双轮通过 {progress["high_speed"]}', flush=True)
            return record
        with futures.ThreadPoolExecutor(max_workers=workers) as pool:
            records = list(pool.map(measure, nodes))
        if initial_records is not None and not modern:
            return records, initial_endpoint_count
        if controls['node_count']:
            controls['after'] = upload_precheck(None)
            controls['valid'] = upload_speed.sample_passed(controls['after'], upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET)
            if not controls['valid']:
                raise RuntimeError('上行预检结束直连对照异常，不据此淘汰或发布')
        else:
            controls['valid'] = True  # No TCP-qualified candidate needed an upload.
    return records, initial_endpoint_count if initial_records is not None else len(tcp_jobs)


def merge_shards(bundle, parts, count, preflight_only=False):
    modern = bundle.get('selection_policy_version') == qp.VERSION
    if len(parts) != count or {p['index'] for p in parts} != set(range(count)):
        raise ValueError('缺少分片，拒绝发布')
    combined = {}
    for part in parts:
        if part.get('bundle_id') != bundle['id']:
            raise ValueError('分片来源批次不一致，拒绝发布')
        if part['count'] != count:
            raise ValueError('分片数量不一致')
        subset = shard_nodes(bundle['nodes'], part['index'], count)
        definitions = {n['name']: n for n in subset}
        expected = set(definitions)
        rows = part['records']
        if len(rows) != len(expected) or {r['id'] for r in rows} != expected:
            raise ValueError('分片存在漏测、重复或串片节点')
        by_id = {r['id']: r for r in rows}
        if bundle.get('early_upload_precheck'):
            controls = part.get('upload_precheck_controls') or {}
            tested = 0 if modern and preflight_only else sum(r['entry']['status'] == 'passed' for r in rows)
            if controls.get('valid') is not True or controls.get('node_count') != tested:
                raise ValueError('上行预检缺少分片对照或检测计数不一致')
            if tested and not all(upload_speed.sample_passed(controls.get(k) or {},
                    upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET) for k in ('before', 'after')):
                raise ValueError('上行预检直连对照未通过，拒绝发布')
        eligible = {endpoint_key(n) for n in subset if tcp_supported(n) and
                    by_id[n['name']].get('precheck', {}).get('status') == 'passed'}
        if part['endpoint_count'] != len(eligible):
            raise ValueError('TCP 入口统计不完整')
        for record in rows:
            if modern and not qp.modern(record):
                raise ValueError('节点缺少本轮稳定性优先策略版本')
            node = definitions[record['id']]
            if bundle.get('parallel_observation') and any(record.get(key) != node[field] for key, field in (('server', 'server'), ('port', 'port'), ('protocol', 'type'))):
                raise ValueError('节点与本轮定义不一致')
            pre = record.get('precheck', {})
            if bundle.get('dual_204'):
                if pre.get('version') != 2 or set(pre.get('targets') or {}) != set(PRECHECK_URLS):
                    raise ValueError('节点缺少双目标204证据')
                for label, item in pre['targets'].items():
                    if item.get('round_count') != 3 or len(item.get('attempts', [])) != 3:
                        raise ValueError('双目标204缺少三轮证据')
                    expected = summarize_rounds([{label: a} for a in item['attempts']], (label,))[label]
                    if item != expected:
                        raise ValueError('双目标204汇总与原始证据不一致')
                    if any(a['status'] == 'passed' and (a.get('http_status') != 204 or a.get('sample_bytes') != 0
                           or a.get('final_url') != PRECHECK_URLS[label]) for a in item['attempts']):
                        raise ValueError('双目标204通过证据不是原地址无正文204')
                if pre != combine_204(pre['targets']):
                    raise ValueError('双目标204联合门槛被绕过')
            if pre.get('round_count') != 3 or len(pre.get('attempts', [])) != 3:
                raise ValueError('节点缺少三轮 204 检测')
            passed = sum(a.get('status') == 'passed' for a in pre['attempts'])
            if pre.get('passed_count') != passed or (pre.get('status') == 'passed') != (passed == 3):
                raise ValueError('204 汇总与三轮结果不一致')
            if record['entry']['status'] != 'unknown' and pre['status'] != 'passed':
                raise ValueError('204 未通过却进入 TCP 阶段')
            if pre['status'] != 'passed' and (record['entry'].get('attempts') != 0 or record.get('websites')):
                raise ValueError('204 未通过却执行后续阶段')
            early = record.get('upload_precheck') or {}
            uses_early = bundle.get('early_upload_precheck') or 'upload_precheck' in record
            if uses_early:
                expected_status = ('passed', 'failed') if record['entry']['status'] == 'passed' and not (modern and preflight_only) else ('skipped',)
                if early.get('status') not in expected_status:
                    raise ValueError('上行预检漏测或国内TCP未通过却已测速')
                if early.get('status') == 'passed' and not upload_speed.sample_passed(
                        early, upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET):
                    raise ValueError('3MB上行预检证据不完整或超出预算')
            should_web = not preflight_only and record['entry']['status'] == 'passed' and (modern or not uses_early or early.get('status') == 'passed')
            if not should_web and record.get('websites'):
                raise ValueError('上行预检或前置阶段未通过却检测了网站')
            if should_web and (not record.get('websites') or any(
                    record['websites'].get(site, {}).get('round_count') not in ((WEBSITE_ROUNDS,) if site in OVERSEAS_SITES else (1, 2) if modern else (1,)) or
                    len(record['websites'].get(site, {}).get('attempts', [])) != record['websites'].get(site, {}).get('round_count')
                    for site in DAILY_POST_SITES)):
                raise ValueError('通过节点缺少海外三轮或trace 单轮检测')
            if (not preflight_only and bundle.get('service_checks_enabled')
                    and (record.get('download') or {}).get('status') == 'passed'
                    and not service_probes.complete(record.get('service_checks'))):
                raise ValueError('1MB通过节点缺少本轮补充服务检测')
            if record.get('websites'):
                for label, item in record['websites'].items():
                    if any(a.get('status') == 'verification_required'
                           and not confirmed_cloudflare_challenge(label, a) for a in item['attempts']):
                        raise ValueError('Cloudflare 验证标记缺少可靠响应证据')
                    if any(a.get('status') == 'login_required' and not confirmed_reddit_login(label, a) for a in item['attempts']):
                        raise ValueError('Reddit登录标记缺少可靠响应证据')
                    expected = summarize_rounds([{label: attempt} for attempt in item['attempts']], (label,))[label]
                    if any(item.get(key) != expected[key] for key in ('status', 'passed_count', 'median_elapsed_ms',
                            'p95_elapsed_ms', 'jitter_ms', 'median_ttfb_ms', 'failure_count', 'slow_count',
                            'accepted_count', 'verification_required_count')):
                        raise ValueError('网站汇总与逐轮响应结果不一致')
                    if item.get('login_required_count', 0) != expected['login_required_count']:
                        raise ValueError('Reddit登录汇总与逐轮响应结果不一致')
            if record['entry']['status'] == 'passed' and pre['status'] != 'passed':
                raise ValueError('节点未按阶段筛选')
            if bundle.get('website_tls_hard_gate') and should_web:
                failed_sites = website_tls_failures(record)
                evidence = record.get('website_tls') or {}
                if evidence.get('sites') != failed_sites or evidence.get('status') != ('failed' if failed_sites else 'passed'):
                    raise ValueError('网站TLS硬筛选记录与原始请求不一致')
            # Eligibility here is based only on evidence available before this stage.
            # Later TLS failures still reject the node, but cannot erase a completed handshake.
            should_tls = should_web and required_websites_passed(record) and not pre_application_tls_failure(record)
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
        login = sum(a.get('status') == 'login_required' and confirmed_reddit_login(label, a) for a in attempts)
        accepted = passed + verified + login
        status = ('passed' if passed == len(rounds)
                  else ('login_required' if login else 'verification_required') if accepted == len(rounds)
                  else 'needs_review' if any(a['status'] == 'needs_review' for a in attempts)
                  else 'unstable' if accepted
                  else 'slow' if any(a['status'] == 'slow' for a in attempts) else 'failed')
        delays = [a['elapsed_ms'] for a in attempts if a.get('elapsed_ms') is not None and a['status'] == 'passed']
        all_delays = sorted(a['elapsed_ms'] for a in attempts if a.get('elapsed_ms') is not None)
        headers = [a['ttfb_ms'] for a in attempts if a.get('ttfb_ms') is not None]
        summarized[label] = {'status': status, 'passed_count': passed, 'round_count': len(rounds),
                              'verification_required_count': verified, 'login_required_count': login, 'accepted_count': accepted,
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
    return (item.get('status') in ('verification_required', 'login_required') and len(attempts) == rounds
            and all(a.get('status') == 'passed' or confirmed_page_exception(label, a) for a in attempts))


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
    if qp.modern(record):
        sites = record.get('websites') or {}
        return all(qp.accepted(label, sites.get(label) or {}, confirmed_page_exception)
                   for label in REQUIRED_SITES) and all(qp.accepted(
                       label, sites.get(label) or {}, confirmed_page_exception, trace=True) for label in REQUIRED_TRACES)
    return all(page_rounds_accepted(label, (record.get('websites') or {}).get(label) or {})
        for label in REQUIRED_SITES) and all(
        (record.get('websites') or {}).get(label, {}).get('status') == 'passed'
        and record['websites'][label].get('round_count') == 1
        and record['websites'][label].get('passed_count') == 1
        for label in REQUIRED_TRACES)


def destination_certificate_failure(record):
    return bool(service_probes.certificate_errors(record.get('service_checks'))) or any(attempt.get('tls_error_kind') == 'certificate_verification_failed'
        for item in (record.get('websites') or {}).values()
        for attempt in item.get('attempts', [item]))


def website_tls_failures(record):
    return sorted(label for label, item in (record.get('websites') or {}).items()
        if any(a.get('tls_error_kind') or a.get('error_type') == 'SSLError'
               for a in item.get('attempts', [item])))


def destination_tls_failure(record):
    return destination_certificate_failure(record) or bool(website_tls_failures(record)) or (qp.modern(record) and any(
        qp.tls_errors(record.get(key)) for key in ('upload_precheck', 'upload', 'download',
            'medium_speed_download', 'high_speed_download', 'application_quality', 'post_upload_tls')))


def pre_application_tls_failure(record):
    """Only the website and early-upload evidence exists at application-TLS entry."""
    return bool(website_tls_failures(record)) or (qp.modern(record) and qp.tls_errors(record.get('upload_precheck')))


def web_quality_eligible(record):
    if not qp.modern(record) and 'upload_precheck' in record and not upload_speed.sample_passed(record['upload_precheck'], upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET):
        return False
    if destination_tls_failure(record):
        return False
    if 'post_upload_tls' in record and not app_tls.passed(record['post_upload_tls']):
        return False
    if 'stability' in record and not stability.quality_passed(record['stability'], CORE_MEDIAN_MS, CORE_TAIL_MS, CORE_JITTER_MS):
        return False
    if not required_websites_passed(record) or not app_tls.passed(record.get('app_tls')):
        return False
    if qp.modern(record):
        return True  # Successful-request latency ranks candidates; it is no extra hard cap.
    sites = record.get('websites') or {}
    for label in CORE_SITES:
        item = sites.get(label) or {}
        if item.get('status') == 'verification_required' and page_rounds_accepted(label, item):
            continue
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
    if not qp.modern(record) and 'upload_precheck' in record and not upload_speed.sample_passed(record['upload_precheck'], upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET):
        return False
    if destination_tls_failure(record):
        return False
    if 'post_upload_tls' in record and not app_tls.passed(record['post_upload_tls']):
        return False
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
    if qp.modern(record):
        return True
    for label in CORE_SITES:
        item = (record.get('websites') or {}).get(label) or {}
        if item.get('status') == 'verification_required' and page_rounds_accepted(label, item):
            continue
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
    uplink = record.get('upload') or {}
    upload_ok = upload_speed.passed(uplink)
    upload_rate = uplink.get('speed_mbps') or 0
    if qp.modern(record):
        upload_ok = qp.upload_observed(record)
        upload_rate = uplink.get('observed_speed_mbps') or 0
    measured = (record.get('high_speed_download') if high_speed_eligible(record) else
                record.get('medium_speed_download') if medium_speed.passed(record.get('medium_speed_download') or {})
                else downloaded)
    down_mbps = (measured.get('speed_mib_s') or 0) * 1048576 * 8 / 1_000_000
    # Within the same 250ms worst-response band, prefer the weaker direction
    # of the two measured rates rather than rewarding download alone.
    response_band = math.ceil(temporal_tail / 250) if upload_ok and math.isfinite(temporal_tail) else temporal_tail
    duplex = min(down_mbps, upload_rate) if upload_ok else 0
    prefix = ()
    if temporal.get('version') in continuous_stability.VERSIONS:
        metrics = continuous_stability.metrics(temporal)
        core = continuous_stability.core_metrics(temporal)
        p95 = max((x['p95_ms'] for x in core.values()), default=math.inf)
        jitter = max((x['iqr_ms'] for x in core.values()), default=math.inf)
        prefix = (-metrics['success_rate'], metrics['maximum_consecutive_failures'],
                  metrics.get('maximum_recovery_seconds', 0), *quality_history.rank(record), p95, jitter) if qp.modern(record) else (
                  -metrics['success_rate'], metrics['maximum_consecutive_failures'], p95, jitter)
    return prefix + (downloaded.get('status') != 'passed', not web_quality_eligible(record), response_band,
            -duplex, -(uplink.get('speed_ratio') or 0) if upload_ok else 0,
            *web_rank_metrics(record), -website_count(record), -connectivity_count(record),
            temporal_tail,
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


def render_comparison(base, records, mapping, require_stability=False, require_upload=False):
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
        and ((qp.upload_observed(r) if qp.modern(r) else upload_speed.passed(r.get('upload'))) if require_upload or 'upload' in r else True)
        and (app_tls.passed(r.get('post_upload_tls')) if require_upload else True)
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
            core_latencies = [stability.core_metrics(record['stability']).get(label, {}).get('median_ms') for label in CORE_SITES]
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
    recommended_pool = strict
    modern_strict = [r for r in strict if qp.modern(r) and stability.passed(r.get('stability'))]
    if modern_strict:
        best = max(continuous_stability.metrics(r['stability'])['success_rate'] for r in modern_strict)
        recommended_pool = [r for r in modern_strict
            if continuous_stability.metrics(r['stability'])['success_rate'] >= min(.99, best)
            and not continuous_stability.metrics(r['stability']).get('unrecovered_at_end')
            and ((r.get('quality_history') or {}).get('measured_runs', 0) < 2 or
                 ((r['quality_history'].get('success_rate') or 0) >= .99 and not r['quality_history'].get('failed_entry_runs')))]
    recommended = [r['name'] for r in recommended_pool]
    regional = [r['name'] for r in ranked if regional_eligible(r)]
    def group(name, names):
        return {'name': name, 'type': 'select' if name == '🚀 全局选择' else 'url-test', 'proxies': names or ['REJECT'],
                'url': GROUP_TEST_URL, 'interval': 300, 'lazy': False,
                'timeout': 5000, 'expected-status': GROUP_TEST_STATUS,
                **({'default-selected': '⭐ 综合优选'} if name == '🚀 全局选择' else {'tolerance': 50})}
    config['proxies'] = proxies
    choices = ['⭐ 综合优选', medium_speed.GROUP, '⚡ 高速下载', '🏠 非机房 IP', REGIONAL_GROUP, 'DIRECT']
    choices.extend(node['name'] for node in proxies)
    config['proxy-groups'] = [
        group('🚀 全局选择', choices),
        group('⭐ 综合优选', recommended), group(medium_speed.GROUP, medium),
        group('⚡ 高速下载', high), group('🏠 非机房 IP', non_dc), group(REGIONAL_GROUP, regional),
    ]
    if mobile_control_paths(config):
        raise ValueError('配置包含解码后的控制字符，拒绝发布到手机')
    return config


def eligible_for_upload(records, mapping):
    return [r for r in records if r['id'] in mapping and r['entry']['status'] == 'passed'
            and (r.get('download') or {}).get('status') == 'passed'
            and (web_quality_eligible(r) or regional_eligible(r))]


def merge_uplink(bundle, records, stage, mapping):
    if stage.get('bundle_id') != bundle['id']:
        raise ValueError('上行复测批次不一致')
    rows = stage.get('records') or []
    expected = {r['id']: r for r in records}
    if len(rows) != len(expected) or {r['id'] for r in rows} != set(expected):
        raise ValueError('上行复测节点缺失或重复')
    eligible = {r['id'] for r in eligible_for_upload(records, mapping)}
    diagnostic = stage.get('diagnostic') or {}
    measured = diagnostic.get('nodes') or []
    if (diagnostic.get('node_count') != len(eligible) or len(measured) != len(eligible)
            or {r['id'] for r in measured} != eligible):
        raise ValueError('上行复测范围与本轮候选不一致')
    if eligible and (diagnostic.get('controls_valid') is not True
            or not all(upload_speed.passed((diagnostic.get('controls') or {}).get(k)) for k in ('before', 'after'))
            or not stability.core_healthy(diagnostic.get('core_health') or {})):
        raise ValueError('上行复测环境对照异常')
    evidence = {r['id']: r for r in measured}
    for row in rows:
        original = expected[row['id']]
        if {k: v for k, v in row.items() if k not in ('upload', 'post_upload_tls')} != original:
            raise ValueError('上行复测修改了原网站或下载证据')
        if row['id'] in eligible:
            for key in ('upload', 'post_upload_tls'):
                if row.get(key) != evidence[row['id']].get(key) or not isinstance(row.get(key), dict):
                    raise ValueError('上行复测缺少对应原始证据')
            if (row['upload'].get('precheck') or {}) != original.get('upload_precheck'):
                raise ValueError('上行复测复用的预检不属于本轮节点')
        elif 'upload' in row or 'post_upload_tls' in row:
            raise ValueError('非候选节点出现上行复测')
    # Mutate only after validating the entire artifact.
    for row in rows:
        if row['id'] in eligible:
            expected[row['id']].update(upload=row['upload'], post_upload_tls=row['post_upload_tls'])
    return diagnostic


def reuse_measurements(bundle, records, cached, source_run):
    """Metadata reuse never substitutes for validated raw shard/upload/observer artifacts."""
    rows = cached.get('nodes') or []
    by_id = {r['id']: r for r in rows}
    if (len(rows) != len(records) or len(by_id) != len(rows) or set(by_id) != {r['id'] for r in records}
            or cached.get('parseable_count') != len(records)
            or cached.get('input_unique_count') != bundle['input_count']):
        raise ValueError('恢复报告不属于本轮完整节点集合')
    original_time = cached.get('measurements_updated_at') or cached['updated_at']
    s.datetime.fromisoformat(original_time)
    keys = ('server', 'port', 'protocol', 'precheck', 'entry', 'upload_precheck',
            'websites', 'exit', 'exit_consistent', 'app_tls', 'download',
            'medium_speed_download', 'high_speed_download', 'upload', 'post_upload_tls', 'service_checks')
    for row in records:
        old = by_id[row['id']]
        if any(row.get(key) != old.get(key) for key in keys):
            raise ValueError('恢复报告与原始检测证据不一致')
        current_stable, previous_stable = row.get('stability') or {}, old.get('stability') or {}
        if any(current_stable.get(key) != previous_stable.get(key)
               for key in ('version', 'attempts', 'peer_completed_offset_seconds', 'status')):
            raise ValueError('恢复报告与持续观察原始证据不一致')
    for row in records:
        old = by_id[row['id']]
        for key in ('ip_type', 'ip_reputation'):
            if key in old:
                row[key] = copy.deepcopy(old[key])
        if row.get('stability') and old['stability'].get('updated_at'):
            row['stability']['updated_at'] = old['stability']['updated_at']
    bundle['measurements_updated_at'] = original_time
    return {'source_run': source_run, 'measurements_updated_at': original_time, 'new_probes': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--phase', choices=('all', 'prepare', 'preflight', 'probe', 'observe', 'uplink-stage', 'publish', 'repair', 'web-recheck', 'medium-recheck', 'stability-recheck', 'uplink-recheck'), default='all')
    parser.add_argument('--sample', help='Optional fixture; default pulls ALL subscriptions')
    parser.add_argument('--work-dir', default='.node-work/availability')
    parser.add_argument('--shard-index', type=int, default=0)
    parser.add_argument('--shard-count', type=int, default=4)
    parser.add_argument('--results-dir', default='.node-work/shards')
    parser.add_argument('--preflight-dir', default='.node-work/preflight')
    parser.add_argument('--observations-dir', default='.node-work/observations')
    parser.add_argument('--reuse-report', help='Validated same-run report to preserve measurement time and IP metadata without querying again')
    parser.add_argument('--source-run', help='Source Actions run for publication recovery')
    parser.add_argument('--uplink-result', default='.node-work/uplink/uplink-stage.json')
    parser.add_argument('--refresh-ip-reputation', action='store_true', help='Refresh optional IP metadata in repair mode')
    parser.add_argument('--chain-front-limit-per-region', type=int, default=10)
    parser.add_argument('--chain-front-total', type=int, default=30)
    parser.add_argument('--chain-front-min-sites', type=int, default=1)
    parser.add_argument('--chain-rounds', type=int, default=2)
    parser.add_argument('--chain-concurrency', type=int, default=20)
    parser.add_argument('--chain-timeout-ms', type=int, default=5000)
    parser.add_argument('--chain-gap-seconds', type=int, default=60)
    parser.add_argument('--chain-disable-verify', action='store_true')
    args = parser.parse_args()
    root = Path(args.work_dir).resolve(); root.mkdir(parents=True, exist_ok=True)
    binary = str(Path(args.mihomo).resolve())
    bundle_path = root / 'bundle.json'
    repair_modes = ('repair', 'web-recheck', 'medium-recheck', 'stability-recheck', 'uplink-recheck')
    if args.phase in repair_modes:
        from published_report import load_report
        previous = load_report(Path('连通性报告.json'))
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
                  'selection_policy_version': qp.VERSION,
                  'early_upload_precheck': True, 'service_checks_enabled': True, 'dual_204': True, 'website_tls_hard_gate': True,
                  'parallel_observation': args.phase == 'prepare',
                  'stability_policy': continuous_stability.settings() if args.phase == 'prepare' else stability.settings(),
                  'historical_candidates': historical,
                  'input_count': input_count, 'rejected': rejected, 'services': service_status(),
                  'mobile_rejections': mobile_rejections,
                  'scope': 'fixture' if args.sample else 'all_subscriptions',
                  'prepared_at': s.datetime.now(s.TZ).isoformat(timespec='seconds')}
        bundle['id'] = hashlib.sha256(json.dumps(bundle, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        edge_pool = edge_candidates.collect(nodes)
        (root / 'edgetunnel-candidates.json').write_text(json.dumps(edge_pool, ensure_ascii=False))
        (root / 'edgetunnel-candidates.summary.json').write_text(json.dumps(edge_candidates.summary(edge_pool), ensure_ascii=False))
        bundle_path.write_text(json.dumps(bundle, ensure_ascii=False))
        print(f'全量节点 {input_count}，内核可解析 {len(nodes)}；双204→TCP后立即独立观察；上行仅分级，观察至少10分钟，最终校验证书与全部证据', flush=True)
        if args.phase == 'prepare':
            return
    else:
        bundle = json.loads(bundle_path.read_text())
    nodes = bundle['nodes']
    base, metadata, sources = bundle['base'], bundle['metadata'], bundle['sources']
    input_count, rejected, services = bundle['input_count'], bundle['rejected'], bundle['services']
    mapping = {n['name']: n for n in nodes}
    if args.phase in ('preflight', 'probe', 'observe'):
        subset = shard_nodes(nodes, args.shard_index, args.shard_count)
        controls, seed = {}, None
        if args.phase in ('probe', 'observe') and bundle.get('parallel_observation'):
            pre_parts = [json.loads(p.read_text()) for p in Path(args.preflight_dir).glob('shard-*.json')]
            pre_records, _ = merge_shards(bundle, pre_parts, args.shard_count, preflight_only=True)
            subset_ids = {n['name'] for n in subset}
            seed = [r for r in pre_records if r['id'] in subset_ids]
            controls = copy.deepcopy(next(p['upload_precheck_controls'] for p in pre_parts if p['index'] == args.shard_index))
        if args.phase == 'observe':
            if seed is None:
                raise ValueError('持续观察必须来自同轮前置检测')
            candidates = [r for r in seed if r['entry']['status'] == 'passed'
                and (bundle.get('selection_policy_version') == qp.VERSION or upload_speed.sample_passed(
                    r.get('upload_precheck') or {}, upload_speed.PRECHECK_BYTES, upload_speed.PRECHECK_BUDGET))]
            diagnostic = continuous_stability.observe(candidates, mapping, binary, root)
            result = {'bundle_id': bundle['id'], 'index': args.shard_index, 'count': args.shard_count,
                      'diagnostic': diagnostic}
            (root / f'observation-{args.shard_index}.json').write_text(json.dumps(result, ensure_ascii=False))
            return
        print(f'分片 {args.shard_index + 1}/{args.shard_count}：{len(subset)}节点，阶段{args.phase}', flush=True)
        try:
            records, endpoint_count = probe_pipeline(subset, binary, root,
                interval=.25 * args.shard_count, upload_controls=controls,
                preflight_only=args.phase == 'preflight', initial_records=seed,
                service_check=service_probes.check_fast, policy_version=bundle.get('selection_policy_version'))
        finally:
            (root / 'upload-precheck-controls.json').write_text(json.dumps(controls, ensure_ascii=False, indent=2))
        result = {'bundle_id': bundle['id'], 'index': args.shard_index, 'count': args.shard_count,
                  'records': records, 'endpoint_count': endpoint_count, 'upload_precheck_controls': controls}
        (root / f'shard-{args.shard_index}.json').write_text(json.dumps(result, ensure_ascii=False))
        return
    if args.phase in ('publish', 'uplink-stage'):
        parts = [json.loads(p.read_text()) for p in Path(args.results_dir).glob('shard-*.json')]
        records, endpoint_count = merge_shards(bundle, parts, args.shard_count)
    elif args.phase not in repair_modes:
        controls = {}
        try:
            records, endpoint_count = probe_pipeline(nodes, binary, root, upload_controls=controls,
                service_check=service_probes.check_fast, policy_version=bundle.get('selection_policy_version'))
        finally:
            (root / 'upload-precheck-controls.json').write_text(json.dumps(controls, ensure_ascii=False, indent=2))
    upload_diagnostic = stability_diagnostic = None
    if args.phase == 'uplink-stage':
        candidates = eligible_for_upload(records, mapping)
        upload_diagnostic = upload_speed.recheck(candidates, mapping, binary, root, reuse_precheck=True)
        (root / 'uplink-stage.json').write_text(json.dumps({'bundle_id': bundle['id'],
            'records': records, 'diagnostic': upload_diagnostic}, ensure_ascii=False))
        return
    parallel_publish = args.phase == 'publish' and bundle.get('parallel_observation')
    if parallel_publish:
        stage = json.loads(Path(args.uplink_result).read_text())
        upload_diagnostic = merge_uplink(bundle, records, stage, mapping)
        observations = [json.loads(p.read_text()) for p in Path(args.observations_dir).glob('observation-*.json')]
        stability_diagnostic = continuous_stability.merge(bundle, observations, records, args.shard_count, shard_nodes)
        (root / 'stability-results.json').write_text(json.dumps(stability_diagnostic, ensure_ascii=False))
        (root / 'upload-results.json').write_text(json.dumps(upload_diagnostic, ensure_ascii=False))
    recovery = None
    if args.reuse_report:
        if not parallel_publish or not args.source_run or not args.source_run.isdigit():
            raise ValueError('恢复发布必须提供同批次并行检测证据和运行编号')
        recovery = reuse_measurements(bundle, records, json.loads(Path(args.reuse_report).read_text()), args.source_run)
    if args.phase == 'medium-recheck':
        medium_rechecked_count = recheck_medium_download(records, mapping, binary, root)
    if args.phase == 'web-recheck':
        website_rechecked_count = recheck_websites(records, mapping, binary, root)
    reachable = [r for r in records if r['entry']['status'] == 'passed' and r.get('websites')]
    if args.phase not in repair_modes:
        ip_types = {} if recovery else s.lookup_ip_types(r['exit']['exit_ip'] for r in records if r['exit'])
        for record in records:
            record['sources'] = metadata.get(record['id'], {}).get('sources', [])
            record['candidate_origin'] = metadata.get(record['id'], {}).get('candidate_origin', 'latest_subscriptions')
            if not recovery:
                record['ip_type'] = ip_types.get((record.get('exit') or {}).get('exit_ip'), {'status': 'unknown', 'hosting': None})
    if (args.phase not in repair_modes or args.refresh_ip_reputation) and not recovery:
        eligible_ips = [(r.get('exit') or {}).get('exit_ip') for r in records
                        if (r.get('download') or {}).get('status') == 'passed'
                        and r.get('exit_consistent') is not False]
        reputations = ip_reputation.lookup(eligible_ips, os.environ.get('IPAPI_IS_KEY', ''))
        for record in records:
            record['ip_reputation'] = reputations.get((record.get('exit') or {}).get('exit_ip'),
                {'status': 'unknown', 'provider': 'ipapi.is', 'reason': 'not_eligible'})
    if not parallel_publish and args.phase in ('all', 'publish', 'uplink-recheck'):
        upload_candidates = [r for r in records if r['id'] in mapping
            and r['entry']['status'] == 'passed' and (r.get('download') or {}).get('status') == 'passed'
            and (web_quality_eligible(r) or regional_eligible(r))]
        upload_diagnostic = upload_speed.recheck(upload_candidates, mapping, binary, root,
            reuse_precheck=args.phase in ('all', 'publish'))
    if not parallel_publish and args.phase in ('all', 'publish', 'stability-recheck', 'uplink-recheck'):
        candidates = [r for r in records if r['id'] in mapping
            and r['entry']['status'] == 'passed'
            and (r.get('download') or {}).get('status') == 'passed'
            and (web_quality_eligible(r) or regional_eligible(r))]
        if args.phase in ('stability-recheck', 'uplink-recheck'):
            stability_diagnostic = continuous_stability.observe(candidates, mapping, binary, root, peer=lambda: True)
            observations = {r['id']: r['stability'] for r in stability_diagnostic['nodes']}
            for r in candidates:
                r['stability'] = observations[r['id']]
        else:
            if any(qp.modern(r) for r in candidates):
                stability_diagnostic = continuous_stability.observe(candidates, mapping, binary, root, peer=lambda: True)
                by_id = {r['id']: r['stability'] for r in stability_diagnostic['nodes']}
                for r in candidates:
                    r['stability'] = by_id[r['id']]
            else:
                stability_diagnostic = stability.recheck(candidates, mapping, binary, root)
    requires_stability = (args.phase in ('all', 'publish', 'stability-recheck', 'uplink-recheck')
        or (args.phase in repair_modes
            and previous.get('node_selection_policy', {}).get('requires_time_spaced_stability') is True))
    requires_upload = (args.phase in ('all', 'publish', 'uplink-recheck')
        or (args.phase in repair_modes and any(previous.get('node_selection_policy', {}).get(key) is True
            for key in ('requires_uplink_pass', 'requires_uplink_observation'))))
    history = None
    if any(qp.modern(r) for r in records):
        old_latest = json.loads(Path('最新检测.json').read_text()) if Path('最新检测.json').exists() else {}
        if args.phase in repair_modes or recovery:
            history = old_latest.get('quality_history')
            for record in records:
                record['quality_history'] = quality_history.summarize((history or {}).get('nodes', {}).get(record['id'], []))
        else:
            history = quality_history.update(records, old_latest.get('quality_history'),
                s.datetime.now(s.TZ).isoformat(timespec='seconds'), os.environ.get('GITHUB_RUN_ID', 'local'))
    config = render_comparison(base, records, mapping, require_stability=requires_stability, require_upload=requires_upload)
    history_summary = quality_history.summary(records)
    history_change = quality_history.compare(history_summary, old_latest.get('quality_history_summary')) if history is not None else None
    tested_selected_count = len(config['proxies'])
    config, untested_info = append_untested(config)
    if mobile_control_paths(config):
        raise ValueError('追加后的配置包含控制字符，拒绝发布')
    if args.phase in ('all', 'publish'):
        measurement_end = s.datetime.now(s.TZ).isoformat(timespec='seconds')
        bundle.setdefault('measurements_updated_at', measurement_end)
        write_attempt(root, records, config, REQUIRED_SITES, sources, input_count,
                      measurement_end, required_traces=REQUIRED_TRACES,
                      required_gate=required_websites_passed,
                      stability_policy=(stability_diagnostic or {}).get('settings') or stability.settings(records),
                      measurement_recovery=recovery, publication_root=Path('.'),
                      untested_subscription=untested_info, tested_selected_count=tested_selected_count,
                      quality_history=history, quality_change=history_change)
    if not config['proxies']:
        if args.phase in ('all', 'publish'):
            print('全量检测完成：无符合页面、trace及应用TLS门槛的节点，报告已保存；原订阅未更新', flush=True)
            return
        raise RuntimeError('没有满足综合或台湾／新加坡门槛的节点；保留旧订阅')
    candidate = root / 'selected.yaml'; s.dump(candidate, config)
    checked = subprocess.run([binary, '-t', '-d', str(root), '-f', str(candidate)], capture_output=True, text=True, timeout=90)
    native_error, native_skipped = None, []
    try:
        native_subscription, native_skipped = render_v2rayn(config)
    except (ValueError, KeyError, TypeError) as error:
        native_error = error
    if native_skipped:
        print(f'v2rayN原生订阅跳过 {len(native_skipped)} 个无法完整表达的节点（Clash配置保留）：'
              + '；'.join(f"{x['name']}（{x['reason']}）" for x in native_skipped[:5]), flush=True)
    if checked.returncode or native_error is not None:
        from attempt_report import record_validation
        record_validation(root, config, 'failed', required_websites_passed)
        if (root / 'full-test-report.json').exists():
            from latest_report import write_latest
            failed_report = json.loads((root / 'full-test-report.json').read_text())
            write_latest(failed_report, config, website_gate=required_websites_passed,
                         candidate=True, validation='failed')
        raise RuntimeError('最终订阅校验失败，不发布') from native_error
    if args.phase in ('all', 'publish'):
        from attempt_report import record_validation
        record_validation(root, config, 'passed', required_websites_passed)
    now = s.datetime.now(s.TZ).isoformat(timespec='seconds')
    counts = {v: sum(r['entry']['status'] == v for r in records) for v in ('passed', 'failed', 'unknown')}
    repairing = args.phase in repair_modes
    published_names = {n['name'] for n in config['proxies']}
    published_ids = [r['id'] for r in records if r.get('name') in published_names and r['id'] in mapping]
    is_modern = any(qp.modern(r) for r in records)
    report = {'updated_at': now, 'scope': bundle['scope'], 'schema_version': 22 if is_modern else 21,
              'selection_policy': qp.settings() if any(qp.modern(r) for r in records) else None,
              'quality_history': history, 'quality_history_summary': history_summary, 'quality_change': history_change,
              'untested_subscription': untested_info, 'tested_selected_node_count': tested_selected_count,
              'v2rayn_skipped': native_skipped,
              'website_tls_policy': {'any_tls_error_eliminates': True, 'includes_optional_sites': True},
              'upload_precheck_policy': upload_speed.precheck_settings(is_modern),
              'early_upload_precheck_enabled': previous.get('early_upload_precheck_enabled', False) if repairing else bool(bundle.get('early_upload_precheck')),
              'upload_precheck_counts': {v: sum((r.get('upload_precheck') or {}).get('status', 'unmeasured') == v for r in records)
                                         for v in ('passed', 'failed', 'skipped', 'unmeasured')},
              'upload_precheck_controls': (previous.get('upload_precheck_controls') if repairing else
                  {str(p['index']): p.get('upload_precheck_controls') for p in parts} if args.phase == 'publish' else {'0': controls}),
              'upload_policy': upload_speed.settings(is_modern),
              'upload_recheck': upload_speed.recheck_summary(records, upload_diagnostic,
                  previous.get('upload_recheck') if repairing else None),
              'historical_candidates': bundle.get('historical_candidates', {}),
              'stability_policy': (stability_diagnostic.get('settings', stability.settings(records)) if stability_diagnostic else previous.get('stability_policy', stability.settings(records)) if repairing else stability.settings(records)),
              'stability_recheck': stability.recheck_summary(records, stability_diagnostic,
                  previous.get('stability_recheck') if repairing else None,
                  quality=lambda r: web_quality_eligible(r) or regional_eligible(r)),
              'app_tls_policy': {'version': 2 if is_modern else app_tls.VERSION, 'targets': list(app_tls.TARGETS),
                  'rounds_per_target': app_tls.ROUNDS, 'budget_seconds_per_handshake': app_tls.BUDGET_SECONDS,
                  'requires_trusted_chain_hostname_validity': True, 'android_certificate_pinning_emulated': False},
              'app_tls_counts': {v: sum((r.get('app_tls') or {}).get('status') == v for r in records)
                                 for v in ('passed', 'failed', 'skipped')},
              'post_upload_tls_counts': {v: sum((r.get('post_upload_tls') or {}).get('status') == v for r in records)
                                         for v in ('passed', 'failed')},
              'measurements_updated_at': bundle.get('measurements_updated_at', now),
              'publication_mode': args.phase if repairing else 'full',
              'measurement_recovery': recovery,
              'group_latency_policy': {'url': GROUP_TEST_URL, 'interval_seconds': 300,
                  'timeout_ms': 5000, 'expected_status': GROUP_TEST_STATUS, 'manual_selection': True, 'lazy': False,
                  'global_type': 'select', 'default_global_selection': '⭐ 综合优选',
                  'other_group_type': 'url-test', 'automatic_selection': True, 'tolerance_ms': 50},
              'website_recheck': ({'updated_at': now, 'node_count': website_rechecked_count,
                  'scope': 'available_published_quick_download_passed', 'overseas_rounds': WEBSITE_ROUNDS,
                  'workers': 8, 'jobs': 1,
                  'preserved_measurements': ['HTTPS204', 'domestic_TCP', 'domestic_pages', 'trace', '1MB_download', 'high_speed_download']}
                  if args.phase == 'web-recheck' else previous.get('website_recheck') if repairing else None),
              'cloudflare_classification_update': ({'updated_at': now, 'reclassified_attempts': reclassified_count,
                  'new_measurements': False, 'source': 'captured_cloudflare_challenge_restriction'}
                  if repairing else None),
              'website_measurement_policy': {'version': 9,
                  'navigation_header_sites': ['Facebook', 'WhatsApp'],
                  'headers_audit_run': '38226619641',
                  'chatgpt_api_validation': 'three_rounds_expected_boolean_json',
                  'confirmed_cloudflare_challenge': 'accepted_access_verification_required',
                  'confirmed_reddit_login_prompt': 'accepted_access_login_required',
                  'challenge_in_page_speed_ranking': False,
                  'challenge_can_replace_204_or_trace': False, 'overseas_rounds': WEBSITE_ROUNDS,
                  'domestic_pages_probed_daily': False, 'trace_rounds': 1, 'sample_bytes': 16384,
                  'sample_bytes_overrides': PAGE_SAMPLE_LIMITS,
                  'conditional_response_sample_bytes': {'Reddit_401_403_without_cf_challenge': REDDIT_LOGIN_SAMPLE_BYTES},
                  'max_ttfb_ms': MAX_TTFB_MS, 'max_sample_ms': MAX_SAMPLE_MS,
                  'required_core_sites': list(CORE_SITES), 'required_websites': list(REQUIRED_SITES),
                  'required_websites_rounds': WEBSITE_ROUNDS, 'minimum_accepted_rounds': 2 if is_modern else 3,
                  'one_transport_failure_allowed': is_modern, 'trace_can_replace_required_page': False,
                  'required_traces': list(REQUIRED_TRACES), 'required_trace_rounds': 1,
                  'claude_validation': 'trace_only', 'claude_homepage_tested': False,
                  'core_median_limit_ms': CORE_MEDIAN_MS,
                  'core_p95_limit_ms': CORE_TAIL_MS, 'core_jitter_limit_ms': CORE_JITTER_MS,
                  'min_accepted_overseas_sites': None if is_modern else math.ceil(len(OVERSEAS_SITES) / 2),
                  'eligible_count': sum(web_quality_eligible(r) and (r.get('download') or {}).get('status') == 'passed' for r in records)},
              'mobile_rejections': bundle.get('mobile_rejections', {}),
              'pipeline': True, 'parallel_shards': bundle.get('parallel_shards', args.shard_count if args.phase == 'publish' else 1),
              'website_workers_per_shard': 16,
              'parallel_sites_per_node': previous.get('parallel_sites_per_node', 3) if repairing else SITE_WORKERS,
              'test_targets': previous.get('test_targets', {k: SITES[k] for k in PAGE_SITES}) if repairing else dict(DAILY_SITES),
              'target_categories': previous.get('target_categories', {'overseas': list((previous.get('test_targets') or {})), 'domestic': []}) if repairing else {'overseas': list(OVERSEAS_SITES), 'domestic': [], 'connectivity': list(CONNECTIVITY_SITES)},
              'routing_policy': {'domestic': 'DIRECT', 'overseas': '🚀 全局选择', 'unmatched': '🚀 全局选择', 'group_count': len(config['proxy-groups']), 'version': 2},
              'stages': previous.get('stages', ['TCP', 'websites']) if repairing else ['HTTPS204', 'domestic_TCP', '3MB_upload_precheck', 'websites_and_trace', 'application_TLS', 'quick_download', '5MB_quick_download', '100MB_Cloudflare_download', '100MB_DataPacket_download', 'upload_double', 'post_upload_TLS', 'parallel_continuous_stability' if parallel_publish else 'time_spaced_stability'],
              'precheck_rounds': previous.get('precheck_rounds', 0) if repairing else 3,
              'precheck_policy': previous.get('precheck_policy') if repairing else
                  {'version': 2, 'targets': PRECHECK_URLS, 'rounds_per_target': 3, 'requires_both': True}
                  if bundle.get('dual_204') else {'version': 1, 'targets': {'Google204': SITES['Google204']}, 'rounds_per_target': 3},
              'website_rounds': WEBSITE_ROUNDS if args.phase == 'web-recheck' or not repairing else previous.get('website_rounds', 1),
              'trace_rounds': previous.get('trace_rounds', 1) if repairing else 1,
              'download_test': previous.get('download_test', False) if repairing else True,
              'download_settings': previous.get('download_settings') if repairing else {'url': DOWNLOAD_URL, 'bytes': DOWNLOAD_BYTES, 'budget_seconds': DOWNLOAD_BUDGET, 'rounds': 1, 'read_timeout_seconds': None if is_modern else 1, 'total_deadline': is_modern, 'includes_handshake': True},
              'web_user_agent': previous.get('web_user_agent') if repairing else WEB_USER_AGENT,
              'medium_speed_download_settings': medium_speed.settings(is_modern),
              'medium_speed_download_counts': medium_speed.counts(records),
              'medium_speed_selection_policy': {'group': medium_speed.GROUP, 'requires_5mb_pass': True,
                  'requires_published_eligible_pool': True, 'regional_exception_allowed': True, 'hong_kong_limit': 30, 'other_regions_limit': None,
                  'selected_count': sum(n != 'REJECT' for g in config['proxy-groups'] if g['name'] == medium_speed.GROUP for n in g['proxies'])},
              'medium_speed_recheck': ({'updated_at': now, 'node_count': medium_rechecked_count,
                  'scope': 'published_1mb_passed', 'preserved_measurements': ['204', 'TCP', 'websites', 'app_TLS', '1MB', '100MB_double']}
                  if args.phase == 'medium-recheck' else previous.get('medium_speed_recheck') if repairing else None),
              'high_speed_download_test': previous.get('high_speed_download_test', False) if repairing else True,
              'high_speed_download_settings': ({**previous['high_speed_download_settings'], 'selection_limit': None}
                  if previous.get('high_speed_download_settings') else None) if repairing else high_speed.settings(is_modern),
              'node_selection_policy': {'hong_kong_limit_per_group': 30, 'other_regions_limit': None,
                  'non_datacenter_total_limit': None, 'qualified_pool_only': True,
                  'requires_time_spaced_stability': requires_stability,
                  'requires_uplink_pass': requires_upload and not is_modern, 'requires_uplink_observation': requires_upload,
                  'comprehensive_pool': 'success_rate_at_least_99_percent_or_best_observed_tier_and_recovered' if is_modern else 'all_qualified',
                  'ranking': ('success_rate_then_failure_streak_then_successful_P95_IQR_then_duplex' if parallel_publish else 'core_response_250ms_band_then_min_upload_download_mbps_then_upload_repeat_ratio_then_web_quality'),
                  'requires_domestic_tcp_pass': True, 'requires_application_tls_pass': True,
                  'rejects_explicit_certificate_error_on_any_tested_website': True,
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
              'website_target_count': sum(label in (previous.get('test_targets') or {}) for label in PAGE_SITES) if repairing else len(OVERSEAS_SITES),
              'overseas_target_count': sum(label in (previous.get('test_targets') or {}) for label in OVERSEAS_SITES) if repairing else len(OVERSEAS_SITES),
              'domestic_target_count': sum(label in (previous.get('test_targets') or {}) for label in DOMESTIC_SITES) if repairing else 0,
              'all_websites_passed': sum(all((r.get('websites') or {}).get(label, {}).get('status') == 'passed' for label in OVERSEAS_SITES) for r in records),
              'three_connectivity_passed': sum(connectivity_count(r) == 3 for r in records),
              'download_counts': {v: sum((r.get('download') or {}).get('status') == v for r in records)
                                  for v in ('passed', 'failed', 'skipped')},
              'services': services, 'sources': sources, 'nodes': records}
    report['website_access_summary'] = website_access_summary(latest_cohort(report))
    report['service_checks_policy'] = previous.get('service_checks_policy') if repairing else service_probes.settings()
    report['service_checks_summary'] = service_probes.summary(latest_cohort(report))
    subscription = f'# 分阶段检测；{now}；检测轮数和下载设置见连通性报告\n' + candidate.read_text()
    Path('优选配置.yaml').write_text(subscription)
    # --- @ty.aicoding@1793178193005 ---
    chain_path = Path('链式配置.yaml')
    if args.phase in ('all', 'publish'):
        try:
            chain_config, chain_summary = chain_fronts.build(
                config, records, mapping,
                binary=None if args.chain_disable_verify else binary, root=root,
                limit_per_region=args.chain_front_limit_per_region,
                total_limit=args.chain_front_total, min_sites=args.chain_front_min_sites,
                rounds=args.chain_rounds, concurrency=args.chain_concurrency,
                timeout_ms=args.chain_timeout_ms, gap_seconds=args.chain_gap_seconds)
        except Exception as error:  # never block the main subscription on the optional chain
            print(f'链式配置生成失败，保留单跳：{type(error).__name__}: {error}', flush=True)
            chain_config, chain_summary = None, {'enabled': False, 'reason': 'chain_build_failed'}
        chain_text = candidate.read_text()
        header = (f'# 链式配置；{now}；本轮未挂链（{chain_summary.get("reason", "unknown")}），'
                  f'内容等同优选配置，单跳\n')
        if chain_config is not None:
            s.dump(root / 'chain-selected.yaml', chain_config)
            chain_checked = subprocess.run([binary, '-t', '-d', str(root), '-f', str(root / 'chain-selected.yaml')],
                                           capture_output=True, text=True, timeout=90)
            if chain_checked.returncode == 0:
                chain_text = yaml.safe_dump(chain_config, allow_unicode=True, sort_keys=False)
                header = (f'# 链式配置；{now}；前置 {chain_summary.get("survivors", 0)} 个，'
                          f'对 {chain_summary.get("landings_tested", 0)} 个美国落地实连验证；'
                          f'优选配置未改动\n')
            else:
                chain_summary = {**chain_summary, 'enabled': False, 'reason': 'config_validation_failed'}
        chain_path.write_text(header + chain_text, encoding='utf-8')
        report['chain'] = chain_summary
        print(f'链式配置：{chain_summary.get("enabled")}；候选 {chain_summary.get("candidates", 0)}，'
              f'存活 {chain_summary.get("survivors", 0)}，落地 {chain_summary.get("landings_tested", 0)}；'
              f'原因 {chain_summary.get("reason", "-")}', flush=True)
    elif not chain_path.exists():
        chain_path.write_text(f'# 链式配置；{now}；本阶段未重新生成，沿用单跳\n' + candidate.read_text(),
                              encoding='utf-8')
    Path('v2rayN.txt').write_text(native_subscription, encoding='utf-8')
    if os.environ.get('GITHUB_RUN_ID'):
        report['source_run'] = os.environ['GITHUB_RUN_ID']
    raw_report = json.dumps(report, ensure_ascii=False, separators=(',', ':')) + '\n'
    Path('连通性报告.json').write_text(raw_report)
    (root / 'full-test-report.published.json').write_text(raw_report)
    from latest_report import write_latest
    write_latest(report, config, website_gate=required_websites_passed, validation='passed')
    print(f'分阶段分类完成，配置校验通过；204 {report["precheck_counts"]}；TCP {counts}；下载 {report["download_counts"]}', flush=True)


if __name__ == '__main__':
    main()
