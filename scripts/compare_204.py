"""Cloud-only paired 204 comparison; never publishes or changes production gates."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import json
import os
from pathlib import Path
import statistics
import threading
import time

import mobile_pilot as p
import select_nodes as s

URLS = {'Google': p.SITES['Google204'], 'Cloudflare': 'https://cp.cloudflare.com/generate_204'}


def candidates(bundle, report):
    ids = {r['id'] for r in report['nodes'] if (r.get('entry') or {}).get('status') == 'passed'}
    nodes = [n for n in bundle['nodes'] if n['name'] in ids]
    if {n['name'] for n in nodes} != ids:
        raise ValueError('TCP-passed records do not match source bundle')
    return nodes


def probe(port, url):
    started = time.perf_counter()
    with s.session() as client:
        if port is not None:
            client.proxies = {'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}
        try:
            with client.get(url, stream=True, timeout=(2, 3), allow_redirects=False,
                            verify=True, headers=p.website_headers('Google204')) as response:
                ttfb = (time.perf_counter() - started) * 1000
                body = next(response.iter_content(1), b'')
                return {'status': 'passed' if response.status_code == 204 and not body else 'failed',
                        'http_status': response.status_code, 'body_present': bool(body),
                        'elapsed_ms': round((time.perf_counter()-started)*1000, 1), 'ttfb_ms': round(ttfb, 1)}
        except s.requests.RequestException as error:
            return {'status': 'failed', 'error_type': type(error).__name__,
                    'certificate_error': p.certificate_failure(error),
                    'elapsed_ms': round((time.perf_counter()-started)*1000, 1)}


def inspect(port, index=0):
    results = {label: [] for label in URLS}
    for number in range(3):
        order = list(URLS) if (number + index) % 2 == 0 else list(reversed(URLS))
        for label in order:
            results[label].append(probe(port, URLS[label]))
    output = {}
    for label, attempts in results.items():
        successful = [r['elapsed_ms'] for r in attempts if r['status'] == 'passed']
        output[label] = {'passed': len(successful) == 3, 'success_count': len(successful),
                         'median_ms': statistics.median(successful) if successful else None,
                         'attempts': attempts}
    return output


def category(result):
    g, c = result['Google']['passed'], result['Cloudflare']['passed']
    return 'both' if g and c else 'google_only' if g else 'cloudflare_only' if c else 'neither'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--source-run', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Real probes run only in GitHub Actions')
    bundle, report = [json.loads(Path(x).read_text()) for x in (args.bundle, args.report)]
    if str(report.get('source_run')) != args.source_run:
        raise ValueError('Report source run mismatch')
    nodes = candidates(bundle, report)
    if not nodes:
        raise ValueError('No TCP-passed nodes')
    root = Path('.node-work/compare-204').resolve(); root.mkdir(parents=True, exist_ok=True)
    before = inspect(None)
    listeners, ports = s.make_listeners({'id': n['name']} for n in nodes)
    done, lock = [0], threading.Lock()
    def measure(pair):
        index, node = pair
        result = inspect(ports[node['name']], index)
        with lock:
            done[0] += 1
            if done[0] % 20 == 0 or done[0] == len(nodes):
                print(f'204对照 {done[0]}/{len(nodes)}', flush=True)
        return {'id': node['name'], 'protocol': node['type'], 'results': result, 'category': category(result)}
    with s.Core(str(Path(args.mihomo).resolve()), root, nodes, listeners):
        with ThreadPoolExecutor(max_workers=16) as pool:
            rows = list(pool.map(measure, enumerate(nodes)))
    after = inspect(None)
    valid = all(x[label]['passed'] for x in (before, after) for label in URLS)
    counts = Counter(r['category'] for r in rows)
    result = {'source_run': args.source_run, 'source_report_updated_at': report['updated_at'],
              'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds'),
              'scope': 'all_latest_domestic_tcp_passed_nodes', 'subscription_updated': False,
              'urls': URLS, 'rounds': 3, 'timeout_connect_read_seconds': [2, 3],
              'alternating_order': True, 'node_workers': 16, 'tls_verified': True,
              'direct_controls_valid': valid, 'controls': {'before': before, 'after': after},
              'node_count': len(rows), 'counts': {k: counts[k] for k in ('both','google_only','cloudflare_only','neither')},
              'nodes': rows}
    (root/'summary.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    lines = ['# 国内TCP通过节点：Google／Cloudflare 204对照', '',
             f'来源运行：{args.source_run}；全部国内TCP通过节点 {len(rows)} 个，未按后续上行或网站结果裁剪。',
             '同节点两个地址各三轮，交替先后顺序；三轮全过才通过。严格证书校验，连接／读取超时2／3秒。',
             '这里只比较云端到两个目标的连通性，不更改订阅或生产筛选。', '',
             f'前后直连对照：{"全部通过" if valid else "异常：以下结果需复核，不能据此替换筛选地址"}。', '',
             '| 类别 | 节点数 |', '|---|---:|']
    for key, label in [('both','两者都通过'),('google_only','仅Google通过'),('cloudflare_only','仅Cloudflare通过'),('neither','两者都未通过')]:
        lines.append(f'| {label} | {counts[key]} |')
    lines += ['', f'判定不同：{counts["google_only"] + counts["cloudflare_only"]} 个。', '',
              '| 节点编号 | 协议 | Google成功轮数／延迟 | Cloudflare成功轮数／延迟 |', '|---|---|---|---|']
    for row in rows:
        values=[]
        for label in URLS:
            x=row['results'][label]
            ms=f'{x["median_ms"]:.1f}ms' if x['median_ms'] is not None else '—'
            values.append(f'{x["success_count"]}/3；{ms}')
        lines.append('| '+row['id']+' | '+row['protocol']+' | '+' | '.join(values)+' |')
    (root/'summary.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps(result['counts'], ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
