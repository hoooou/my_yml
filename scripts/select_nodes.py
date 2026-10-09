#!/usr/bin/env python3
"""Refresh public subscriptions, measure real transfers, and generate a Clash config."""
import argparse
import concurrent.futures as futures
import copy
import csv
from datetime import datetime, timezone, timedelta
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import time
from urllib.parse import quote

import requests
import yaml

COUNTRIES = {'HK': '香港', 'TW': '台湾', 'JP': '日本', 'SG': '新加坡', 'US': '美国',
             'KR': '韩国', 'DE': '德国', 'GB': '英国', 'FR': '法国', 'CA': '加拿大',
             'AU': '澳大利亚', 'NL': '荷兰', 'IN': '印度', 'RU': '俄罗斯',
             'FI': '芬兰', 'SE': '瑞典', 'CH': '瑞士', 'CN': '中国', 'VN': '越南'}
CHECK_URL = 'https://www.gstatic.com/generate_204'
DOWNLOAD_URL = 'http://lax.download.datapacket.com/10mb.bin'
FILE_BYTES = 10000000
IP_API_URL = 'http://ip-api.com/batch'
IP_FIELDS = 'status,message,query,countryCode,isp,org,as,mobile,proxy,hosting'
TRACE_URL = 'https://speed.cloudflare.com/cdn-cgi/trace'
TZ = timezone(timedelta(hours=8))


def dump(path, value):
    path.write_text(yaml.safe_dump(value, allow_unicode=True, sort_keys=False), encoding='utf-8')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def session():
    client = requests.Session()
    client.trust_env = False
    return client


class Core:
    def __init__(self, binary, root, nodes, listeners=None):
        self.binary, self.root = binary, root
        self.port, self.secret = free_port(), secrets.token_hex(24)
        occupied = {listener['port'] for listener in listeners or []}
        while self.port in occupied:
            self.port = free_port()
        self.path = root / 'test-core.yaml'
        self.config = {
            'mixed-port': 0, 'allow-lan': False, 'mode': 'rule', 'log-level': 'error',
            'external-controller': f'127.0.0.1:{self.port}', 'secret': self.secret,
            'dns': {'enable': False}, 'tun': {'enable': False}, 'ipv6': True,
            'proxies': nodes, 'rules': ['MATCH,REJECT'], 'listeners': listeners or [],
        }
        self.process = None

    def validate_nodes(self):
        rejected = []
        while self.config['proxies']:
            dump(self.path, self.config)
            result = subprocess.run([self.binary, '-t', '-d', str(self.root), '-f', str(self.path)],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return self.config['proxies'], rejected
            match = re.search(r'proxy (\d+):', result.stdout + result.stderr)
            if not match:
                raise RuntimeError('内核校验失败，无法定位节点；详见本地测试日志')
            index = int(match[1])
            if index >= len(self.config['proxies']):
                raise RuntimeError('内核返回了无效的节点索引')
            rejected.append(self.config['proxies'].pop(index)['name'])
        raise RuntimeError('订阅中没有可被 Mihomo 解析的节点')

    def __enter__(self):
        dump(self.path, self.config)
        self.log = (self.root / 'core.log').open('w')
        self.process = subprocess.Popen([self.binary, '-d', str(self.root), '-f', str(self.path)],
                                        stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(100):
            if self.process.poll() is not None:
                self.__exit__(None, None, None)
                raise RuntimeError('测试内核启动失败')
            try:
                self.get('/version')
                return self
            except requests.RequestException:
                time.sleep(.1)
        self.__exit__(None, None, None)
        raise RuntimeError('测试内核未在限时内就绪')

    def __exit__(self, *_):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.log.close()

    def get(self, path, params=None, timeout=10):
        with session() as client:
            response = client.get(f'http://127.0.0.1:{self.port}{path}', params=params,
                                  headers={'Authorization': f'Bearer {self.secret}'}, timeout=timeout)
            response.raise_for_status()
            return response.json()

    def latency(self, node):
        try:
            data = self.get('/proxies/' + quote(node['name'], safe='') + '/delay',
                            {'url': CHECK_URL, 'timeout': 4000, 'expected': '204'}, timeout=6)
            return node['name'], data['delay']
        except (requests.RequestException, KeyError):
            return node['name'], None


def canonical_node(node):
    if not isinstance(node, dict) or not all(k in node for k in ('type', 'server', 'port')):
        return None
    raw = copy.deepcopy(node)
    raw.pop('name', None)
    # A node must be independently testable, without local interfaces or other proxies.
    if any(k in raw for k in ('dialer-proxy', 'interface-name', 'routing-mark')):
        return None
    if not isinstance(raw['server'], str) or not isinstance(raw['type'], str):
        return None
    try:
        if isinstance(raw['port'], bool) or str(raw['port']) != str(int(raw['port'])):
            return None
        raw['port'] = int(raw['port'])
        if not 1 <= raw['port'] <= 65535:
            return None
    except (ValueError, TypeError, OverflowError):
        return None
    server = raw['server'].strip().rstrip('.')
    if not server:
        return None
    try:
        raw['server'] = str(ipaddress.ip_address(server))
    except ValueError:
        raw['server'] = server.lower()
    raw['type'] = raw['type'].lower()
    if isinstance(raw.get('uuid'), str):
        raw['uuid'] = raw['uuid'].lower()
    return raw


def load_sources(path):
    document = yaml.safe_load(path.read_text(encoding='utf-8'))
    entries = document.get('sources') if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise ValueError('节点来源.yaml 必须包含 sources 列表')
    sources = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('节点来源条目必须是映射')
        if not entry.get('enabled', True):
            continue
        name, url = entry.get('id'), entry.get('url')
        if not isinstance(name, str) or not re.fullmatch('[a-zA-Z0-9_-]+', name):
            raise ValueError('节点来源 id 必须是字母、数字、下划线或短横线')
        if name in sources or not isinstance(url, str) or not url.startswith('https://'):
            raise ValueError('节点来源 id 重复或缺少 HTTPS 地址')
        sources[name] = entry
    return sources


def collect(base, root, cache=None, extra_sources=None):
    providers = dict(base.get('proxy-providers') or {})
    for name, provider in (extra_sources or {}).items():
        if name in providers:
            raise ValueError('新增来源 id 与原订阅源重复：' + name)
        providers[name] = provider

    def fetch(item):
        name, provider = item
        info = {'provider': name, 'url': provider.get('url', ''),
                'repository': provider.get('repository', ''), 'downloaded': 0,
                'accepted': 0, 'skipped': 0, 'duplicates': 0, 'unique_added': 0, 'status': 'ok',
                'fetched_at': datetime.now(TZ).isoformat(timespec='seconds')}
        try:
            path = cache / (name + '.txt') if cache else None
            if path and path.exists():
                data = path.read_bytes()
                info['cached'] = True
            else:
                if not info['url'].startswith('https://'):
                    raise ValueError('来源缺少 HTTPS 订阅地址')
                response = requests.get(info['url'], timeout=(10, 25),
                                        headers={'User-Agent': 'mihomo/1.19.32', 'Cache-Control': 'no-cache'})
                response.raise_for_status()
                data = response.content
            content = yaml.safe_load(data)
            nodes = content.get('proxies') if isinstance(content, dict) else None
            if not isinstance(nodes, list) or not nodes:
                raise ValueError('订阅没有非空的 YAML proxies 列表')
            info['sha256'] = hashlib.sha256(data).hexdigest()
            info['downloaded'] = len(nodes)
            return name, nodes, info
        except (requests.RequestException, yaml.YAMLError, ValueError) as error:
            info['status'] = type(error).__name__
            return name, [], info

    identities, source_info = {}, []
    with futures.ThreadPoolExecutor(max_workers=6) as pool:
        for source, nodes, info in pool.map(fetch, providers.items()):
            source_info.append(info)
            for node in nodes:
                raw = canonical_node(node)
                if raw is None:
                    info['skipped'] += 1
                    continue
                info['accepted'] += 1
                identity = hashlib.sha256(json.dumps(raw, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()[:12]
                if identity not in identities:
                    raw['name'] = 'n-' + identity
                    identities[identity] = {'node': raw, 'sources': []}
                    info['unique_added'] += 1
                else:
                    info['duplicates'] += 1
                identities[identity]['sources'].append(source)
    metadata = {item['node']['name']: {'sources': sorted(set(item['sources']))} for item in identities.values()}
    nodes = [item['node'] for item in identities.values()]
    (root / 'sources.json').write_text(json.dumps(source_info, ensure_ascii=False, indent=2))
    return nodes, metadata, source_info


def measure_file(binary, root, node, max_latency):
    name = node['name']
    input_path, output_path = root / (name + '.yaml'), root / (name + '-tested.yaml')
    output_path.unlink(missing_ok=True)
    dump(input_path, {'proxies': [node]})
    command = [binary, '-c', str(input_path), '-output', str(output_path), '-rename=false',
               '-speed-mode', 'download', '-server-url', DOWNLOAD_URL, '-download-size', str(FILE_BYTES),
               '-timeout', '30s', '-concurrent', '1', '-max-latency', f'{max_latency}ms',
               '-max-packet-loss', '20', '-min-download-speed', '0.5']
    try:
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=50)
        (root / (name + '.tsv')).write_text(result.stdout)
        if result.returncode != 0 or not output_path.exists():
            return None
        passed = yaml.safe_load(output_path.read_text()).get('proxies') or []
        if not passed:
            return None
        for row in csv.reader(result.stdout.splitlines(), delimiter='\t'):
            if len(row) < 7 or row[1] != name:
                continue
            speed = re.fullmatch(r'([\d.]+)([KMGT]?B)/s', row[6])
            latency = re.fullmatch(r'(\d+)ms', row[3])
            if not speed or not latency:
                return None
            unit = {'B': 1, 'KB': 1024, 'MB': 1024**2, 'GB': 1024**3, 'TB': 1024**4}[speed[2]]
            return {'id': name, 'file_latency_ms': int(latency[1]),
                    'file_speed_mib_s': float(speed[1]) * unit / 1024**2,
                    'head_failure_percent': float(row[5].rstrip('%'))}
    except (subprocess.TimeoutExpired, yaml.YAMLError, ValueError, KeyError):
        return None
    return None


def query_exit(port, record):
    with session() as client:
        client.proxies = {'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}
        trace = client.get(TRACE_URL, timeout=10)
        trace.raise_for_status()
        fields = dict(line.split('=', 1) for line in trace.text.splitlines() if '=' in line)
        ip = str(ipaddress.ip_address(fields['ip']))
        country = fields.get('loc', '')
        if not re.fullmatch('[A-Z]{2}', country) or country == 'XX' or not ipaddress.ip_address(ip).is_global:
            raise ValueError('出口地区或 IP 无法确认')
        return {**record, 'exit_ip': ip, 'country_code': country}


def download_file(client, expected_sha256=None):
    started, total, digest = time.perf_counter(), 0, hashlib.sha256()
    with client.get(DOWNLOAD_URL, headers={'Cache-Control': 'no-cache', 'Accept-Encoding': 'identity'},
                    stream=True, timeout=(8, 8)) as response:
        response.raise_for_status()
        for chunk in response.iter_content(65536):
            total += len(chunk)
            digest.update(chunk)
            if total > FILE_BYTES or time.perf_counter() - started > 30:
                raise ValueError('测速文件大小异常或下载超过 30 秒')
    elapsed = time.perf_counter() - started
    if total != FILE_BYTES:
        raise ValueError('测速文件未完整下载')
    sha256 = digest.hexdigest()
    if expected_sha256 is not None and sha256 != expected_sha256:
        raise ValueError('测速文件内容与直连对照不一致')
    return total / elapsed / 1024**2, sha256


def verify_exit(port, record, expected_sha256):
    current = query_exit(port, record)
    if current['exit_ip'] != record['exit_ip'] or current['country_code'] != record['country_code']:
        raise ValueError('出口 IP 或地区在分类后发生变化')
    with session() as client:
        client.proxies = {'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}
        measured, _ = download_file(client, expected_sha256)
    effective = min(record['file_speed_mib_s'], measured)
    if effective < .5:
        raise ValueError('复测下载速度低于 0.5 MiB/s')
    return {**record, 'verification_speed_mib_s': round(measured, 3), 'speed_mib_s': round(effective, 3)}


def make_listeners(records):
    # Reserve all ephemeral ports together so nodes cannot share a listener by accident.
    sockets, ports = [], {}
    try:
        for record in records:
            sock = socket.socket()
            sock.bind(('127.0.0.1', 0))
            sockets.append(sock)
            ports[record['id']] = sock.getsockname()[1]
    finally:
        for sock in sockets:
            sock.close()
    listeners = [{'name': 'test-' + name, 'type': 'mixed', 'listen': '127.0.0.1',
                  'port': port, 'proxy': name} for name, port in ports.items()]
    return listeners, ports


def classify_regions(binary, root, alive, mapping):
    classified, failures = [], 0
    for offset in range(0, len(alive), 64):
        batch = alive[offset:offset + 64]
        listeners, ports = make_listeners(batch)
        with Core(binary, root, [mapping[r['id']] for r in batch], listeners):
            with futures.ThreadPoolExecutor(max_workers=16) as pool:
                jobs = [pool.submit(query_exit, ports[r['id']], r) for r in batch]
                for job in futures.as_completed(jobs):
                    try:
                        classified.append(job.result())
                    except (requests.RequestException, ValueError, KeyError):
                        failures += 1
        print(f'地区确认进度 {min(offset + 64, len(alive))}/{len(alive)}，成功 {len(classified)}，失败 {failures}', flush=True)
    classified.sort(key=lambda r: (r['country_code'], r['latency_ms'], r['id']))
    return classified, failures


def lookup_ip_types(ips):
    ips = sorted(set(ips))
    results = {ip: {'status': 'unknown', 'provider': 'ip-api.com', 'hosting': None} for ip in ips}
    with session() as client:
        for offset in range(0, len(ips), 100):
            batch = ips[offset:offset + 100]
            try:
                response = client.post(IP_API_URL, params={'fields': IP_FIELDS}, json=batch, timeout=15)
                if response.status_code == 429:
                    print('IP 类型查询触发限流，剩余地址记为未知', flush=True)
                    break
                response.raise_for_status()
                values = response.json()
                if not isinstance(values, list):
                    raise ValueError('IP 查询返回格式异常')
                for value in values:
                    if not isinstance(value, dict) or value.get('query') not in batch:
                        continue
                    ip = value['query']
                    if value.get('status') == 'success' and type(value.get('hosting')) is bool:
                        results[ip] = {**value, 'provider': 'ip-api.com',
                                       'checked_at': datetime.now(TZ).isoformat(timespec='seconds')}
            except (requests.RequestException, ValueError):
                print(f'IP 类型查询批次失败：{offset + 1}–{offset + len(batch)}，记为未知', flush=True)
                continue
            remaining = int(response.headers.get('X-Rl', '1'))
            if remaining <= 0 and offset + 100 < len(ips):
                wait = min(60, max(1, int(response.headers.get('X-Ttl', '60')) + 1))
                print(f'等待 IP 查询限流窗口 {wait} 秒', flush=True)
                time.sleep(wait)
            elif offset + 100 < len(ips):
                time.sleep(5)  # At most 12 batch requests/minute (service limit: 15).
    return results


def rank(records):
    return sorted(records, key=lambda r: (-r['speed_mib_s'], r['latency_ms'], r['id']))


def select_rankings(records, per_region_limit, non_datacenter_limit):
    regional_ids, residential_ids = {}, []
    seen_ips = set()
    for record in rank(records):
        group = regional_ids.setdefault(record['country_code'], [])
        if len(group) < per_region_limit:
            group.append(record['id'])
        info = record.get('ip_type', {})
        if (info.get('status') == 'success' and info.get('hosting') is False
                and record['exit_ip'] not in seen_ips and len(residential_ids) < non_datacenter_limit):
            residential_ids.append(record['id'])
            seen_ips.add(record['exit_ip'])
    wanted = set(residential_ids) | {name for names in regional_ids.values() for name in names}
    return [r for r in rank(records) if r['id'] in wanted], regional_ids, residential_ids


def measure_regions(binary, speedtest, root, classified, mapping, metadata, settings):
    groups = {}
    for record in classified:
        groups.setdefault(record['country_code'], []).append(record)
    verified, summaries = [], []
    for country, records in sorted(groups.items()):
        summary = {'country_code': country, 'region': COUNTRIES.get(country, country),
                   'classified': len(records), 'file_tested': 0, 'file_passed': 0,
                   'verification_failed': 0, 'qualified': 0}
        print(f"开始 {summary['region']} {country} 文件测速：{len(records)} 个节点", flush=True)
        for offset in range(0, len(records), 64):
            batch = records[offset:offset + 64]
            listeners, ports = make_listeners(batch)
            def measure(record):
                result = measure_file(speedtest, root, mapping[record['id']], settings['max_latency_ms'])
                if result is None:
                    return 'file_failed', None
                combined = {**record, **result, **metadata[record['id']]}
                try:
                    return 'ok', verify_exit(ports[record['id']], combined, settings['file_sha256'])
                except (requests.RequestException, ValueError, KeyError):
                    return 'verification_failed', None
            with Core(binary, root, [mapping[r['id']] for r in batch], listeners):
                with futures.ThreadPoolExecutor(max_workers=4) as pool:
                    for status, result in pool.map(measure, batch):
                        summary['file_tested'] += 1
                        if status != 'file_failed':
                            summary['file_passed'] += 1
                        if status == 'verification_failed':
                            summary['verification_failed'] += 1
                        if result is not None:
                            verified.append(result)
                            summary['qualified'] += 1
                        if summary['file_tested'] % 10 == 0 or summary['file_tested'] == len(records):
                            print(f"{country} 文件测速 {summary['file_tested']}/{len(records)}，完整下载合格 {summary['qualified']}", flush=True)
            (root / 'verified-results.json').write_text(json.dumps(verified, ensure_ascii=False, indent=2))
        summaries.append(summary)
    return verified, summaries


def render_config(base, records, nodes, regional_ids=None, non_datacenter_ids=None):
    config = {key: copy.deepcopy(base[key]) for key in (
        'mixed-port', 'allow-lan', 'mode', 'log-level', 'external-controller', 'dns', 'rules', 'rule-providers') if key in base}
    config['dns']['default-nameserver'] = [ip for ip in config['dns']['default-nameserver']
                                          if not ipaddress.ip_address(ip).is_private]
    references = {rule.split(',')[1] for rule in config['rules'] if rule.startswith('RULE-SET,')}
    config['rule-providers'] = {key: value for key, value in config['rule-providers'].items() if key in references}
    proxies, countries = [], {}
    for record in records:
        region = COUNTRIES.get(record['country_code'], record['country_code'])
        name = f"{region} {record['country_code']} | {record['id'][2:8]} | {record['speed_mib_s']:.2f}MiB/s | {record['latency_ms']}ms"
        node = copy.deepcopy(nodes[record['id']])
        node['name'] = name
        record['name'] = name
        proxies.append(node)
        countries.setdefault(region, []).append(name)
    names = [node['name'] for node in proxies]
    id_names = {record['id']: record['name'] for record in records}
    if regional_ids is not None:
        countries = {COUNTRIES.get(country, country): [id_names[name] for name in ids]
                     for country, ids in sorted(regional_ids.items()) if ids}
    non_dc_names = [id_names[name] for name in non_datacenter_ids or []]
    test = {'url': CHECK_URL, 'expected-status': 204, 'interval': 300, 'timeout': 5000, 'lazy': True}
    config['proxies'] = proxies
    config['proxy-groups'] = [
        {'name': '🚀 全局选择', 'type': 'select', 'proxies': ['⚡ 速度优先', '♻️ 低延迟', '🏠 非机房 IP', '🎯 手动选择', 'DIRECT'] + list(countries)},
        {'name': '⚡ 速度优先', 'type': 'fallback', **test, 'proxies': names},
        {'name': '♻️ 低延迟', 'type': 'url-test', **test, 'tolerance': 50, 'proxies': names},
        {'name': '🎯 手动选择', 'type': 'select', 'proxies': names},
        ({'name': '🏠 非机房 IP', 'type': 'fallback', **test, 'proxies': non_dc_names}
         if non_dc_names else {'name': '🏠 非机房 IP', 'type': 'select', 'proxies': ['REJECT']}),
    ] + [{'name': country, 'type': 'select', 'proxies': group} for country, group in countries.items()]
    return config


def prepare(args, root):
    base = yaml.safe_load(Path(args.base).read_text())
    nodes, metadata, sources = collect(base, root, args.source_cache, load_sources(args.sources))
    print(f'订阅拉取完成：{sum(s["downloaded"] for s in sources)} 个节点，去重后 {len(nodes)} 个', flush=True)
    core = Core(args.mihomo, root, nodes)
    nodes, rejected = core.validate_nodes()
    mapping = {node['name']: node for node in nodes}
    alive = []
    with core:
        control = core.get('/proxies/DIRECT/delay', {'url': CHECK_URL, 'timeout': 5000, 'expected': '204'})
        print(f'延迟测试直连对照成功：{control["delay"]}ms', flush=True)
        with futures.ThreadPoolExecutor(max_workers=32) as pool:
            jobs = [pool.submit(core.latency, node) for node in nodes]
            for count, job in enumerate(futures.as_completed(jobs), 1):
                name, delay = job.result()
                if delay is not None and 0 < delay <= args.max_latency_ms:
                    alive.append({'id': name, 'latency_ms': delay})
                if count % 100 == 0 or count == len(nodes):
                    print(f'延迟测速 {count}/{len(nodes)}，合格 {len(alive)}', flush=True)
    classified, region_failures = classify_regions(args.mihomo, root, alive, mapping)
    if not classified:
        raise RuntimeError('没有通过延迟和地区确认的节点；保留旧配置')
    ip_types = lookup_ip_types(r['exit_ip'] for r in classified)
    for record in classified:
        record['ip_type'] = ip_types[record['exit_ip']]
    known = sum(info.get('status') == 'success' for info in ip_types.values())
    non_dc = sum(info.get('status') == 'success' and info.get('hosting') is False for info in ip_types.values())
    print(f'IP 类型检测：独立出口 {len(ip_types)}，确认 {known}，非机房 {non_dc}，未知 {len(ip_types) - known}', flush=True)
    with session() as client:
        _, fingerprint = download_file(client)
    settings = {'latency_url': CHECK_URL, 'download_url': DOWNLOAD_URL,
                'max_latency_ms': args.max_latency_ms, 'minimum_speed_mib_s': .5,
                'file_bytes': FILE_BYTES, 'verification_bytes': FILE_BYTES, 'file_sha256': fingerprint,
                'per_region_limit': args.per_region_limit, 'non_datacenter_limit': args.non_datacenter_limit,
                'file_candidates': 'all_region_classified_nodes', 'ip_type_provider': 'ip-api.com',
                'non_datacenter_criterion': 'status=success and hosting=false; unique exit IPs'}
    state = {'base': base, 'nodes': mapping, 'metadata': metadata, 'sources': sources,
             'invalid_count': len(rejected), 'latency_passed': len(alive), 'classified': classified,
             'region_failures': region_failures, 'ip_types': ip_types, 'settings': settings,
             'test_origin': args.test_origin}
    (root / 'state.json').write_text(json.dumps(state, ensure_ascii=False))
    print(f'地区分类完成：{len(classified)} 个节点，{len(set(r["country_code"] for r in classified))} 个地区；测速文件直连对照通过', flush=True)


def publish(args, root, state):
    selected, regional_ids, non_dc_ids = select_rankings(state['verified'],
        state['settings']['per_region_limit'], state['settings']['non_datacenter_limit'])
    if not selected:
        raise RuntimeError('没有通过完整文件测速的节点；保留旧配置，不发布空配置')
    for region in state['regions']:
        region['selected_count'] = len(regional_ids.get(region['country_code'], []))
        region['selected_ids'] = regional_ids.get(region['country_code'], [])
    config = render_config(state['base'], selected, state['nodes'], regional_ids, non_dc_ids)
    candidate_path = root / 'selected-config.yaml'
    dump(candidate_path, config)
    checked = subprocess.run([args.mihomo, '-t', '-d', str(root), '-f', str(candidate_path)],
                             capture_output=True, text=True, timeout=90)
    if checked.returncode != 0:
        raise RuntimeError('最终配置内核校验失败；保留旧配置')
    timestamp = datetime.now(TZ).isoformat(timespec='seconds')
    sources, regions, ip_types = state['sources'], state['regions'], state['ip_types']
    qualified_non_dc = [r for r in state['verified'] if r['ip_type'].get('status') == 'success' and r['ip_type'].get('hosting') is False]
    report = {'updated_at': timestamp, 'test_origin': state['test_origin'], 'tool': 'faceair/clash-speedtest v1.8.8',
              'input_count': sum(s['downloaded'] for s in sources), 'unique_count': len(state['nodes']) + state['invalid_count'],
              'invalid_count': state['invalid_count'], 'duplicate_count': sum(s['duplicates'] for s in sources),
              'skipped_count': sum(s['skipped'] for s in sources), 'latency_passed': state['latency_passed'],
              'region_classified': len(state['classified']), 'region_failures': state['region_failures'],
              'file_tested': sum(r['file_tested'] for r in regions), 'file_passed': sum(r['file_passed'] for r in regions),
              'verification_failed': sum(r['verification_failed'] for r in regions), 'qualified_count': len(state['verified']),
              'selected_count': len(selected), 'sources': sources, 'regions': regions, 'settings': state['settings'],
              'ip_checks': {'unique_ips': len(ip_types), 'known': sum(i.get('status') == 'success' for i in ip_types.values()),
                            'unknown': sum(i.get('status') != 'success' for i in ip_types.values()), 'results': ip_types},
              'non_datacenter': {'qualified_nodes': len(qualified_non_dc),
                                'qualified_unique_ips': len({r['exit_ip'] for r in qualified_non_dc}),
                                'selected_count': len(non_dc_ids), 'selected_ids': non_dc_ids}, 'nodes': selected}
    header = f'# 自动生成；更新时间：{timestamp}\n# 每地区最多 {state["settings"]["per_region_limit"]} 个；非机房 IP 最多 {state["settings"]["non_datacenter_limit"]} 个；合计去重 {len(selected)} 个\n'
    Path('优选配置.yaml').write_text(header + candidate_path.read_text(), encoding='utf-8')
    Path('测速报告.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    rows = ['# 节点测速报告', '', f'更新时间：{timestamp}', '',
            f'测速地点：{state["test_origin"]}。输入 {report["input_count"]} 个，去重后 {report["unique_count"]} 个；'
            f'延迟合格 {report["latency_passed"]} 个，出口地区确认成功 {report["region_classified"]} 个，全部进行文件测速；'
            f'完整文件复测合格 {report["qualified_count"]} 个，最终合并入选 {len(selected)} 个。', '',
            f'测速文件：[{DOWNLOAD_URL}]({DOWNLOAD_URL})；每次完整下载 {FILE_BYTES:,} 字节（10 MB）。'
            '下载速度取工具测速和完整文件复测中的较低值，按速度降序、延迟升序排名。', '',
            '地区和 IP 通过节点访问 Cloudflare trace 确认；分类后出口 IP 或地区变化的节点剔除。'
            '初筛延迟为 Google 204 请求耗时，文件延迟为测速工具 6 次 HEAD 请求平均值。MiB/s 是下载速度，HEAD 失败率不是 ICMP 丢包率。', '',
            '[IP 类型依据 ip-api.com 的 hosting 字段](https://ip-api.com/docs/api:json)。只有明确返回成功且 hosting=false 的地址进入非机房候选；'
            '未知地址不纳入，非机房组按出口 IP 去重。这个标签是数据库分类结果，不保证是住宅 IP，也不代表特定网站解锁。', '',
            '## 各地区筛选', '', '| 地区 | 分类成功 | 文件测速 | 工具通过 | 完整复测合格 | 地区入选 |',
            '|---|---:|---:|---:|---:|---:|']
    for region in regions:
        rows.append(f"| {region['region']} {region['country_code']} | {region['classified']} | {region['file_tested']} | "
                    f"{region['file_passed']} | {region['qualified']} | {region['selected_count']} |")
    rows += ['', f"非机房 IP：文件复测合格 {len(qualified_non_dc)} 个节点、{report['non_datacenter']['qualified_unique_ips']} 个独立出口，"
             f"入选 {len(non_dc_ids)} 个；IP 类型检测未知 {report['ip_checks']['unknown']} 个独立出口。",
             '地区与非机房分组可共享节点，最终配置取两个榜单的并集；各地区分组仍只含该地区最多 30 个。', '',
             '## 入选节点', '', '| 地区 | 节点 | 出口 IP | 初筛延迟 ms | 文件延迟 ms | 下载 MiB/s | HEAD 失败率 | IP 类型 | 来源 |',
             '|---|---|---|---:|---:|---:|---:|---|---|']
    for record in selected:
        info = record['ip_type']
        label = '未知' if info.get('status') != 'success' else ('机房' if info['hosting'] else '非机房')
        rows.append(f'| {COUNTRIES.get(record["country_code"], record["country_code"])} | {record["id"]} | {record["exit_ip"]} | '
                    f'{record["latency_ms"]} | {record["file_latency_ms"]} | {record["speed_mib_s"]:.3f} | '
                    f'{record["head_failure_percent"]:.1f}% | {label} | {", ".join(record["sources"])} |')
    rows += ['', '## 本次来源拉取', '',
             f"重复 {report['duplicate_count']} 个，无法独立测试或格式无效 {report['skipped_count']} 个。新增唯一数按来源顺序统计。", '',
             '| 来源 | 拉取状态 | 原始节点 | 新增唯一 | 重复 | 跳过 | 内容 SHA-256（前 12 位） |',
             '|---|---|---:|---:|---:|---:|---|']
    for source in sources:
        link = source['repository'] or source['url']
        label = f"[{source['provider']}]({link})" if link else source['provider']
        rows.append(f"| {label} | {source['status']} | {source['downloaded']} | {source['unique_added']} | "
                    f"{source['duplicates']} | {source['skipped']} | {source.get('sha256', '')[:12]} |")
    Path('测速报告.md').write_text('\n'.join(rows) + '\n', encoding='utf-8')
    print(f'生成成功：{len(selected)} 个去重节点；非机房 IP 分组 {len(non_dc_ids)} 个；最终 Mihomo 配置校验通过', flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--speedtest', required=True)
    parser.add_argument('--base', default='聚合配置.yaml')
    parser.add_argument('--sources', type=Path, default=Path('节点来源.yaml'))
    parser.add_argument('--work-dir', default='.node-work')
    parser.add_argument('--source-cache', type=Path)
    parser.add_argument('--stage', choices=['all', 'prepare', 'measure', 'publish'], default='all')
    parser.add_argument('--per-region-limit', '--limit', dest='per_region_limit', type=int, default=30)
    parser.add_argument('--non-datacenter-limit', type=int, default=30)
    parser.add_argument('--max-latency-ms', type=int, default=1000)
    parser.add_argument('--test-origin', default='local')
    args = parser.parse_args()
    if min(args.per_region_limit, args.non_datacenter_limit, args.max_latency_ms) < 1:
        parser.error('节点上限和最大延迟必须为正数')
    args.mihomo, args.speedtest = str(Path(args.mihomo).resolve()), str(Path(args.speedtest).resolve())
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if args.stage in ('all', 'prepare'):
        prepare(args, root)
    if args.stage == 'prepare':
        return
    state = json.loads((root / 'state.json').read_text())
    if args.stage in ('all', 'measure'):
        verified, regions = measure_regions(args.mihomo, args.speedtest, root, state['classified'],
                                            state['nodes'], state['metadata'], state['settings'])
        state.update(verified=verified, regions=regions)
        (root / 'state.json').write_text(json.dumps(state, ensure_ascii=False))
    if args.stage in ('all', 'publish'):
        publish(args, root, state)


if __name__ == '__main__':
    main()
