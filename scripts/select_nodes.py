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
DOWNLOAD_URL = 'https://speed.cloudflare.com/__down?bytes=8388608'
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
               '-speed-mode', 'download', '-server-url', DOWNLOAD_URL, '-download-size', '8388608',
               '-timeout', '10s', '-concurrent', '1', '-max-latency', f'{max_latency}ms',
               '-max-packet-loss', '20', '-min-download-speed', '0.5']
    try:
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=35)
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


def verify_exit(port, record):
    with session() as client:
        client.proxies = {'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}
        trace = client.get(TRACE_URL, timeout=10)
        trace.raise_for_status()
        fields = dict(line.split('=', 1) for line in trace.text.splitlines() if '=' in line)
        ip = str(ipaddress.ip_address(fields['ip']))
        country = fields.get('loc', '')
        if not re.fullmatch('[A-Z]{2}', country) or country == 'XX':
            raise ValueError('出口地区未知')
        size = 4 * 1024 * 1024
        started = time.perf_counter()
        total = 0
        with client.get(f'https://speed.cloudflare.com/__down?bytes={size}',
                        headers={'Cache-Control': 'no-cache', 'Accept-Encoding': 'identity'},
                        stream=True, timeout=(8, 8)) as response:
            response.raise_for_status()
            for chunk in response.iter_content(65536):
                total += len(chunk)
                if time.perf_counter() - started > 12:
                    raise ValueError('复测下载超过 12 秒')
        elapsed = time.perf_counter() - started
        if total != size:
            raise ValueError('复测文件未完整下载')
        measured = total / elapsed / 1024**2
        effective = min(record['file_speed_mib_s'], measured)
        if effective < .5:
            raise ValueError('复测下载速度低于 0.5 MiB/s')
        return {**record, 'exit_ip': ip, 'country_code': country,
                'verification_speed_mib_s': round(measured, 3), 'speed_mib_s': round(effective, 3)}


def render_config(base, records, nodes):
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
    test = {'url': CHECK_URL, 'expected-status': 204, 'interval': 300, 'timeout': 5000, 'lazy': True}
    config['proxies'] = proxies
    config['proxy-groups'] = [
        {'name': '🚀 全局选择', 'type': 'select', 'proxies': ['⚡ 速度优先', '♻️ 低延迟', '🎯 手动选择', 'DIRECT'] + list(countries)},
        {'name': '⚡ 速度优先', 'type': 'fallback', **test, 'proxies': names},
        {'name': '♻️ 低延迟', 'type': 'url-test', **test, 'tolerance': 50, 'proxies': names},
        {'name': '🎯 手动选择', 'type': 'select', 'proxies': names},
    ] + [{'name': country, 'type': 'select', 'proxies': group} for country, group in countries.items()]
    return config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--speedtest', required=True)
    parser.add_argument('--base', default='聚合配置.yaml')
    parser.add_argument('--sources', type=Path, default=Path('节点来源.yaml'))
    parser.add_argument('--work-dir', default='.node-work')
    parser.add_argument('--source-cache', type=Path)
    parser.add_argument('--limit', type=int, default=30)
    parser.add_argument('--candidate-limit', type=int, default=150)
    parser.add_argument('--max-latency-ms', type=int, default=1000)
    parser.add_argument('--test-origin', default='local')
    args = parser.parse_args()
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    base = yaml.safe_load(Path(args.base).read_text())
    nodes, metadata, sources = collect(base, root, args.source_cache, load_sources(args.sources))
    print(f'订阅拉取完成：{sum(s["downloaded"] for s in sources)} 个节点，去重后 {len(nodes)} 个', flush=True)
    core = Core(str(Path(args.mihomo).resolve()), root, nodes)
    nodes, rejected = core.validate_nodes()
    mapping = {node['name']: node for node in nodes}
    alive = []
    with core:
        # A positive control distinguishes a broken test target/network from dead nodes.
        control = core.get('/proxies/DIRECT/delay', {'url': CHECK_URL, 'timeout': 5000, 'expected': '204'})
        print(f'测试目标对照成功：{control["delay"]}ms；开始逐节点验证', flush=True)
        with futures.ThreadPoolExecutor(max_workers=32) as pool:
            jobs = [pool.submit(core.latency, node) for node in nodes]
            for count, job in enumerate(futures.as_completed(jobs), 1):
                name, delay = job.result()
                if delay is not None and 0 < delay <= args.max_latency_ms:
                    alive.append({'id': name, 'latency_ms': delay})
                if count % 100 == 0 or count == len(nodes):
                    print(f'连通性进度 {count}/{len(nodes)}，延迟合格 {len(alive)}', flush=True)
    alive.sort(key=lambda record: (record['latency_ms'], record['id']))
    candidates = alive[:args.candidate_limit]
    (root / 'latency-results.json').write_text(json.dumps(alive, ensure_ascii=False, indent=2))
    print(f'开始文件测速：{len(candidates)} 个低延迟候选，使用 faceair/clash-speedtest v1.8.8', flush=True)
    measured = []
    # Parallelize two nodes, each with a single download stream; final verification is serial.
    with futures.ThreadPoolExecutor(max_workers=2) as pool:
        jobs = {pool.submit(measure_file, str(Path(args.speedtest).resolve()), root, mapping[r['id']], args.max_latency_ms): r for r in candidates}
        for count, job in enumerate(futures.as_completed(jobs), 1):
            result = job.result()
            if result:
                measured.append({**jobs[job], **result, **metadata[result['id']]})
            if count % 10 == 0 or count == len(candidates):
                print(f'文件测速进度 {count}/{len(candidates)}，速度合格 {len(measured)}', flush=True)
    measured.sort(key=lambda r: (-r['file_speed_mib_s'], r['latency_ms']))
    (root / 'speed-results.json').write_text(json.dumps(measured, ensure_ascii=False, indent=2))
    selected, exit_failures = [], 0
    for record in measured:
        listener_port = free_port()
        listeners = [{'name': 'verify', 'type': 'mixed', 'listen': '127.0.0.1', 'port': listener_port, 'proxy': record['id']}]
        try:
            with Core(str(Path(args.mihomo).resolve()), root, [mapping[record['id']]], listeners):
                selected.append(verify_exit(listener_port, record))
                print(f'出口及完整下载复测通过 {len(selected)}：{selected[-1]["country_code"]} {selected[-1]["speed_mib_s"]:.2f}MiB/s', flush=True)
        except (requests.RequestException, ValueError, KeyError):
            exit_failures += 1
        # Test more than 30 before choosing the final 30, since verification may change order.
        if len(selected) >= args.limit * 2:
            break
    selected.sort(key=lambda r: (-r['speed_mib_s'], r['latency_ms'], r['id']))
    selected = selected[:args.limit]
    if not selected:
        raise RuntimeError('没有通过完整下载和出口地区验证的节点；保留旧配置，不发布空配置')
    config = render_config(base, selected, mapping)
    candidate_path = root / 'selected-config.yaml'
    dump(candidate_path, config)
    checked = subprocess.run([str(Path(args.mihomo).resolve()), '-t', '-d', str(root), '-f', str(candidate_path)],
                             capture_output=True, text=True, timeout=90)
    if checked.returncode != 0:
        raise RuntimeError('最终配置内核校验失败；保留旧配置')
    timestamp = datetime.now(TZ).isoformat(timespec='seconds')
    report = {'updated_at': timestamp, 'test_origin': args.test_origin,
              'tool': 'faceair/clash-speedtest v1.8.8', 'input_count': sum(s['downloaded'] for s in sources),
              'unique_count': len(nodes) + len(rejected), 'invalid_count': len(rejected),
              'duplicate_count': sum(s['duplicates'] for s in sources),
              'skipped_count': sum(s['skipped'] for s in sources),
              'latency_passed': len(alive), 'file_tested': len(candidates), 'file_passed': len(measured),
              'exit_failures': exit_failures, 'selected_count': len(selected), 'sources': sources,
              'settings': {'latency_url': CHECK_URL, 'download_url': DOWNLOAD_URL,
                           'max_latency_ms': args.max_latency_ms, 'minimum_speed_mib_s': .5,
                           'file_bytes': 8388608, 'verification_bytes': 4194304,
                           'candidate_limit': args.candidate_limit, 'target_count': args.limit},
              'nodes': selected}
    header = f'# 自动生成；更新时间：{timestamp}\n# 测速地点：{args.test_origin}；实际入选 {len(selected)} 个节点\n'
    Path('优选配置.yaml').write_text(header + candidate_path.read_text(), encoding='utf-8')
    Path('测速报告.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    rows = ['# 节点测速报告', '', f'更新时间：{timestamp}', '',
            f'测速地点：{args.test_origin}。输入 {report["input_count"]} 个节点，去重后 {report["unique_count"]} 个；'
            f'延迟合格 {len(alive)} 个，对其中 {len(candidates)} 个进行文件测速，最终入选 {len(selected)} 个。', '',
            '地区通过节点访问 Cloudflare trace 查询实际出口 IP。速度取 8 MiB 文件测速和 4 MiB 完整下载复测中的较低值；'
            'MiB/s 是文件下载速度，不是 Mbps。初筛延迟是 Google 204 请求耗时，文件延迟是测速工具 6 次 HEAD 请求的平均值。', '',
            '低延迟候选先测，未进入候选列表的节点不保证比入选节点慢。测速结果仅代表更新时间及该运行地点；'
            '不代表本机速度、UDP 可用性或特定网站解锁。', '',
            '| 地区 | 节点 | 出口 IP | 初筛延迟 ms | 文件延迟 ms | 下载 MiB/s | HEAD 失败率 | 来源 |',
            '|---|---|---|---:|---:|---:|---:|---|']
    for record in selected:
        rows.append(f'| {COUNTRIES.get(record["country_code"], record["country_code"])} | {record["id"]} | {record["exit_ip"]} | '
                    f'{record["latency_ms"]} | {record["file_latency_ms"]} | {record["speed_mib_s"]:.3f} | {record["head_failure_percent"]:.1f}% | {", ".join(record["sources"])} |')
    rows += ['', '## 本次来源拉取', '',
             f"合并原配置订阅与新增来源，重复 {report['duplicate_count']} 个，无法独立测试或格式无效 {report['skipped_count']} 个。"
             '只读取来源的 proxies，不执行其规则、分组、脚本或控制端口设置。', '',
             '新增唯一节点按来源顺序统计；同一节点的全部来源记录在上表与 JSON 报告中。', '',
             '| 来源 | 拉取状态 | 原始节点 | 新增唯一 | 重复 | 跳过 | 内容 SHA-256（前 12 位） |',
             '|---|---|---:|---:|---:|---:|---|']
    for source in sources:
        link = source['repository'] or source['url']
        label = f"[{source['provider']}]({link})" if link else source['provider']
        rows.append(f"| {label} | {source['status']} | {source['downloaded']} | {source['unique_added']} | "
                    f"{source['duplicates']} | {source['skipped']} | {source.get('sha256', '')[:12]} |")
    Path('测速报告.md').write_text('\n'.join(rows) + '\n', encoding='utf-8')
    print(f'生成成功：{len(selected)} 个节点；最终 Mihomo 配置校验通过', flush=True)


if __name__ == '__main__':
    main()
