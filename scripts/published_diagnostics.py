#!/usr/bin/env python3
"""Bounded cloud recheck of two published snapshots; never write subscriptions."""
import argparse
import concurrent.futures as futures
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import quote

import yaml
import availability as a
import select_nodes as s

NATIVE_URLS = {
    'production_https': a.SITES['Google204'],
    'gstatic_https': 'https://www.gstatic.com/generate_204',
    'gstatic_http': 'http://www.gstatic.com/generate_204',
}


def snapshot(ref):
    if not re.fullmatch(r'[0-9a-f]{7,40}', ref):
        raise ValueError('Snapshot must be a commit SHA')
    def read(path):
        return subprocess.check_output(['git', 'show', ref + ':' + path], text=True)
    config = yaml.safe_load(read('优选配置.yaml'))
    report = json.loads(read('连通性报告.json'))
    mapping = {n['name']: n for n in config['proxies']}
    rows = {r['id']: r for r in report['nodes'] if r.get('name') in mapping}
    if set(rows) != set(report['published_node_ids']):
        raise ValueError('Published report and configuration disagree')
    nodes = {key: {**mapping[row['name']], 'name': key} for key, row in rows.items()}
    return report, rows, nodes


def native_delay(core, identity, url):
    try:
        result = core.get('/proxies/' + quote(identity, safe='') + '/delay',
                          {'url': url, 'timeout': 4000, 'expected': '204'}, timeout=6)
        delay = result.get('delay')
        if type(delay) not in (int, float) or delay <= 0:
            return {'status': 'failed', 'reason': '无有效延迟'}
        return {'status': 'passed', 'delay_ms': delay}
    except s.requests.RequestException as error:
        return {'status': 'failed', 'error_type': type(error).__name__}


def run(binary, root, current_ref, previous_ref):
    current, current_rows, current_nodes = snapshot(current_ref)
    previous, previous_rows, previous_nodes = snapshot(previous_ref)
    nodes = {**previous_nodes, **current_nodes}
    if not 0 < len(nodes) <= 150:
        raise ValueError('Diagnostic node budget exceeded')
    listeners, ports = s.make_listeners({'id': key} for key in nodes)
    pace = a.Pace(interval=1)
    started = datetime.now(s.TZ).isoformat(timespec='seconds')
    with s.Core(str(Path(binary).resolve()), root, list(nodes.values()), listeners) as core:
        def measure(identity):
            node = nodes[identity]
            pre = a.precheck_204(ports[identity])
            native = {label: native_delay(core, identity, url) for label, url in NATIVE_URLS.items()}
            pages = {label: a.check_site(ports[identity], label, a.SITES[label])
                     for label in ('Google', 'YouTube')}
            row = {'id': identity, 'protocol': node['type'],
                   'current_published': identity in current_nodes,
                   'previous_published': identity in previous_nodes,
                   'precheck': pre, 'native_delay': native, 'websites': pages}
            print('Published snapshot recheck complete: ' + identity, flush=True)
            return row
        with futures.ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(measure, sorted(nodes)))
        # Only authenticated/cloud-healthy samples need a fresh domestic comparison.
        # Every requested endpoint is deduplicated; one request/second globally.
        eligible = {a.endpoint_key(nodes[r['id']]) for r in rows
                    if r['precheck']['status'] == 'passed' and a.tcp_supported(nodes[r['id']])}
        def tcp(endpoint):
            rounds = [a.probe_xxapi(endpoint, pace) for _ in range(3)]
            return endpoint, rounds
        with futures.ThreadPoolExecutor(max_workers=4) as pool:
            tcp_rows = dict(pool.map(tcp, sorted(eligible)))
        for row in rows:
            rounds = tcp_rows.get(a.endpoint_key(nodes[row['id']]), [])
            row['domestic_tcp'] = {'rounds': rounds,
                'counts': dict(Counter(r['status'] for r in rounds)),
                'status': 'measured' if rounds else 'skipped'}
    def counts(group):
        subset = [r for r in rows if r[group]]
        return {'total': len(subset), 'precheck': dict(Counter(r['precheck']['status'] for r in subset)),
            'native_delay': {label: dict(Counter(r['native_delay'][label]['status'] for r in subset))
                             for label in NATIVE_URLS},
            'domestic_tcp_three_passes': sum(r['domestic_tcp']['counts'].get('passed') == 3 for r in subset)}
    result = {'scope': 'diagnostic_only_no_subscription_change', 'checked_at': started,
        'completed_at': datetime.now(s.TZ).isoformat(timespec='seconds'),
        'current_ref': current_ref, 'previous_ref': previous_ref,
        'current_published_at': current['updated_at'], 'previous_published_at': previous['updated_at'],
        'native_delay_timeout_ms': 4000, 'native_urls': NATIVE_URLS,
        'current': counts('current_published'), 'previous': counts('previous_published'), 'nodes': rows}
    (root / 'summary.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    lines = ['# 已发布节点复测', '', '独立云端诊断，不修改订阅；云端结果需要与手机实际访问对照。', '',
        f"当前配置：{result['current']}；上一版：{result['previous']}", '',
        '|节点|协议|本版/前版|204三轮|内核同URL/HTTPS/HTTP|Google/YouTube|国内TCP三轮|',
        '|---|---|---|---|---|---|---|']
    for r in rows:
        delays = '/'.join(str(r['native_delay'][k].get('delay_ms', r['native_delay'][k]['status']))
                          for k in NATIVE_URLS)
        pages = '/'.join(r['websites'][k]['status'] for k in ('Google', 'YouTube'))
        lines.append('|' + '|'.join([r['id'], r['protocol'],
            f"{r['current_published']}/{r['previous_published']}", r['precheck']['status'],
            delays, pages, str(r['domestic_tcp']['counts'])]) + '|')
    text = '\n'.join(lines) + '\n'
    (root / 'summary.md').write_text(text)
    print(text, flush=True)
    return result


def tls_only(binary, root, current_ref, previous_ref):
    current, _, current_nodes = snapshot(current_ref)
    previous, _, previous_nodes = snapshot(previous_ref)
    nodes = {**previous_nodes, **current_nodes}
    if not 0 < len(nodes) <= 150:
        raise ValueError('Diagnostic node budget exceeded')
    control = a.app_tls.check(None)
    if not a.app_tls.passed(control):
        raise RuntimeError('Cloud direct TLS controls failed; diagnose target/service before promotion')
    listeners, ports = s.make_listeners({'id': key} for key in nodes)
    with s.Core(str(Path(binary).resolve()), root, list(nodes.values()), listeners):
        def measure(identity):
            result = a.app_tls.check(ports[identity])
            print('Application TLS recheck complete: ' + identity, flush=True)
            return {'id': identity, 'protocol': nodes[identity]['type'],
                    'current_published': identity in current_nodes,
                    'previous_published': identity in previous_nodes, 'app_tls': result}
        with futures.ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(measure, sorted(nodes)))
    result = {'scope': 'diagnostic_only_no_subscription_change', 'direct_control': control,
        'current_ref': current_ref, 'previous_ref': previous_ref,
        'checked_at': datetime.now(s.TZ).isoformat(timespec='seconds'), 'nodes': rows,
        'current_counts': dict(Counter(r['app_tls']['status'] for r in rows if r['current_published'])),
        'previous_counts': dict(Counter(r['app_tls']['status'] for r in rows if r['previous_published']))}
    (root / 'summary.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    lines = ['# 应用TLS云端筛选对照', '',
        '标准TLS证书链、域名和有效期校验；不模拟Android证书固定或手机Wi-Fi链路。', '',
        f"当前：{result['current_counts']}；前版：{result['previous_counts']}", '',
        '|节点|协议|本版/前版|应用TLS|失败原因|', '|---|---|---|---|---|']
    for row in rows:
        errors = Counter(attempt.get('error_type', 'passed')
            for item in row['app_tls']['targets'].values() for attempt in item['attempts'])
        lines.append('|' + '|'.join([row['id'], row['protocol'],
            f"{row['current_published']}/{row['previous_published']}", row['app_tls']['status'], str(dict(errors))]) + '|')
    text = '\n'.join(lines) + '\n'; (root / 'summary.md').write_text(text); print(text, flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--current-ref', required=True)
    parser.add_argument('--previous-ref', required=True)
    parser.add_argument('--tls-only', action='store_true')
    args = parser.parse_args()
    root = Path('.node-work/published-diagnostics').resolve()
    root.mkdir(parents=True, exist_ok=True)
    (tls_only if args.tls_only else run)(args.mihomo, root, args.current_ref, args.previous_ref)


if __name__ == '__main__':
    main()
