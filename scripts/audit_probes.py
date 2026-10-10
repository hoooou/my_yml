#!/usr/bin/env python3
"""Read-only small cloud audit of website restrictions and repeated TCP outcomes."""
import argparse
import concurrent.futures as futures
from collections import Counter
import json
from pathlib import Path

import availability as a
import claude_diagnostics as d
import select_nodes as s

TARGETS = ('Perplexity', 'StackOverflow', 'Reddit', 'TikTok', 'Gemini', 'Google', '京东', '哔哩哔哩')


def tcp_samples(nodes, rows):
    available = {n['name'] for n in nodes}
    candidates = sorted((r for r in rows if r['id'] in available
        and r['precheck']['status'] == 'passed' and r['entry']['status'] == 'failed'),
        key=lambda r: (r['precheck'].get('median_elapsed_ms') or float('inf'), r['id']))
    selected, seen, protocols = [], set(), set()
    for row in candidates:
        key = row['server'], row['port']
        if key not in seen and row['protocol'] not in protocols:
            selected.append(row); seen.add(key); protocols.add(row['protocol'])
        if len(selected) == 6:
            break
    for row in candidates:
        key = row['server'], row['port']
        if len(selected) >= 6:
            break
        if key not in seen:
            selected.append(row); seen.add(key)
    return selected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    root = Path('.node-work/probe-audit').resolve(); root.mkdir(parents=True, exist_ok=True)
    bundle = json.loads(Path(args.bundle).read_text()); report = json.loads(Path(args.report).read_text())
    mapping = {n['name']: n for n in bundle['nodes']}
    healthy = d.choose_samples(bundle['nodes'], report['nodes'], 4)
    failed = tcp_samples(bundle['nodes'], report['nodes'])
    udp = []; seen_udp = set()
    for row in report['nodes']:
        key = row['server'], row['port']
        if (row['id'] in mapping and row['protocol'] == 'hysteria2'
                and row['precheck']['status'] == 'passed' and key not in seen_udp):
            udp.append(row); seen_udp.add(key)
        if len(udp) == 2:
            break
    selected = {r['id']: r for r in healthy + failed + udp}
    listeners, ports = s.make_listeners(selected.values())
    website_results, tcp_results, udp_results = [], [], []
    pace = a.Pace(interval=1)
    with s.Core(str(Path(args.mihomo).resolve()), root,
                [mapping[n] for n in selected], listeners):
        def website(row):
            port = ports[row['id']]
            before = a.precheck_204(port)
            probes = {}
            if before['status'] == 'passed':
                def site(label):
                    return label, {'production': a.check_site(port, label, a.SITES[label]),
                        'bot_capture': d.requests_probe(port, d.p.WEB_USER_AGENT, label),
                        'browser_ua_capture': d.requests_probe(port, d.BROWSER_UA, label)}
                with futures.ThreadPoolExecutor(max_workers=2) as pool:
                    probes = dict(pool.map(site, TARGETS))
            after = a.precheck_204(port)
            print('Website audit complete: ' + row['id'], flush=True)
            return {'id': row['id'], 'previous_exit': row.get('exit'),
                    'before_204': before, 'after_204': after, 'sites': probes}
        with futures.ThreadPoolExecutor(max_workers=4) as pool:
            website_results = list(pool.map(website, healthy))
        # Compare six previously failed endpoints and two positive controls, one request/second.
        for row in failed + healthy[:2]:
            pre = a.precheck_204(ports[row['id']])
            rounds = [a.probe_xxapi((row['server'], row['port']), pace) for _ in range(3)]
            tcp_results.append({'id': row['id'], 'protocol': row['protocol'],
                'previous_entry': row['entry'], 'current_204': pre,
                'tcp_rounds': rounds, 'tcp_counts': dict(Counter(x['status'] for x in rounds))})
            print('TCP audit complete: ' + row['id'], flush=True)
        for row in udp:
            port = ports[row['id']]
            pre = a.precheck_204(port)
            sites, download = {}, {'status': 'skipped'}
            if pre['status'] == 'passed':
                targets = {label: a.SITES[label] for label in (*a.REQUIRED_SITES, *a.REQUIRED_TRACES)}
                rounds = [a.check_sites(port, targets)]
                rounds += [a.check_sites(port, {label: a.SITES[label] for label in a.REQUIRED_SITES}) for _ in range(2)]
                sites = a.summarize_rounds(rounds, a.REQUIRED_SITES)
                sites.update(a.summarize_rounds(rounds[:1], a.REQUIRED_TRACES))
                if a.required_websites_passed({'websites': sites}):
                    download = a.quick_download(port)
            udp_results.append({'id': row['id'], 'protocol': 'hysteria2', 'precheck': pre,
                'websites': sites, 'download': download,
                'domestic_entry': {'status': 'unknown', 'reason': '云端认证实连，不代表国内UDP可达'}})
            print('Hysteria2 protocol audit complete: ' + row['id'], flush=True)
    result = {'scope': 'diagnostic_only_no_subscription_change',
        'source_report_updated_at': report['updated_at'], 'websites': website_results,
        'tcp': tcp_results, 'hysteria2_cloud_protocol': udp_results}
    (root / 'summary.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    lines = ['# 异常淘汰小样本诊断', '', '独立诊断不修改订阅或放宽门槛；仅正常响应才通过。', '',
        '|样本|站点|原检测|原UA响应|浏览器UA响应|标题|跳转|', '|---|---|---|---|---|---|---|']
    for row in website_results:
        for label, data in row['sites'].items():
            capture = data['bot_capture']
            cells = [row['id'], label, data['production']['status'],
                str(capture.get('http_status', capture.get('error_type'))),
                str(data['browser_ua_capture'].get('http_status', data['browser_ua_capture'].get('error_type'))),
                capture.get('title') or '', capture.get('headers', {}).get('location') or '']
            lines.append('|' + '|'.join(str(c).replace('|', '/') for c in cells) + '|')
    lines += ['', '|TCP样本|协议|上轮TCP|本轮204|三次TCP状态|', '|---|---|---|---|---|']
    for row in tcp_results:
        lines.append('|' + '|'.join((row['id'], row['protocol'], row['previous_entry']['status'],
            row['current_204']['status'], str(row['tcp_counts']))) + '|')
    lines += ['', '|Hysteria2样本|协议实连204（三轮）|12页面加Claude trace|1MB下载|国内UDP|',
              '|---|---|---|---|---|']
    for row in udp_results:
        lines.append('|' + '|'.join((row['id'], row['precheck']['status'],
            str(a.required_websites_passed(row)), row['download']['status'], '未验证')) + '|')
    text = '\n'.join(lines) + '\n'; (root / 'summary.md').write_text(text); print(text, flush=True)


if __name__ == '__main__':
    main()
