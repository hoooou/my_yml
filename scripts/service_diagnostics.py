"""Small cloud-only validation of supplementary endpoints; never publish nodes."""
import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import yaml

from bandwidth_gate import BandwidthGate
from detection_report import service_checks_table
import select_nodes as s
import service_probes as probes
from availability import precheck_204


def choose_samples(report, config, limit=4):
    by_name = {n['name']: n for n in config['proxies']}
    selected = set(report.get('published_node_ids') or [])
    rows = [r for r in report['nodes'] if r['id'] in selected and r.get('name') in by_name]
    rows.sort(key=lambda r: ((r.get('exit') or {}).get('country_code') or '', r['id']))
    samples, countries, ips = [], set(), set()
    for diverse in (True, False):
        for row in rows:
            country = (row.get('exit') or {}).get('country_code')
            ip = (row.get('exit') or {}).get('exit_ip')
            if row in samples or ip and ip in ips or diverse and country in countries:
                continue
            samples.append(row); countries.add(country)
            if ip:
                ips.add(ip)
            if len(samples) >= limit:
                return samples
    return samples


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--samples', type=int, choices=range(1, 5), default=4)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Real service probes must run in GitHub Actions')
    root = Path('.node-work/service-diagnostics').resolve(); root.mkdir(parents=True, exist_ok=True)
    report = json.loads(Path('连通性报告.json').read_text())
    config = yaml.safe_load(Path('优选配置.yaml').read_text())
    rows = choose_samples(report, config, args.samples)
    if not rows:
        raise RuntimeError('No mapped published samples')
    by_name = {n['name']: n for n in config['proxies']}
    nodes = [{**by_name[r['name']], 'name': r['id']} for r in rows]
    listeners, ports = s.make_listeners(rows)
    gate = BandwidthGate()
    controls = {'before': probes.check(None, gate)}
    outcomes = []
    with s.Core(str(Path(args.mihomo).resolve()), root, nodes, listeners):
        for row in rows:
            port = ports[row['id']]
            item = {'id': row['id'], 'country_code': (row.get('exit') or {}).get('country_code'),
                    'precheck': precheck_204(port), 'service_checks': probes.check(port, gate)}
            outcomes.append(item)
            print('服务检测完成：' + row['id'], flush=True)
    controls['after'] = probes.check(None, gate)
    followups = []
    target = (controls['before']['targets']['TikTokTrace']).get('redirect_target')
    for _ in range(2):
        if not target or urlparse(target).hostname not in ('www.tiktok.com', 'tiktok.com'):
            break
        response, _ = probes.fetch(None, target)
        followups.append(response)
        target = response.get('redirect_target')
    output = {'settings': probes.settings(), 'controls': controls, 'nodes': outcomes,
              'service_checks_summary': probes.summary(outcomes), 'subscription_updated': False,
              'tiktok_redirect_followups': followups}
    (root / 'summary.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n')
    md = ['# 补充服务小样本验证', '', '只读检测当前订阅的最多4个节点，另测前后GitHub直连对照。', '']
    md += service_checks_table(outcomes)
    md += ['## 逐样本结果', '', '| 样本 | 204三轮 | ChatGPT API | FAST API | Netflix CDN 1MB | TikTok trace |',
           '|---|---|---|---|---|---|']
    for label, checked in [*(('对照' + key, value) for key, value in controls.items()),
                           *((r['id'], r['service_checks']) for r in outcomes)]:
        targets = checked['targets']
        pre = next((r['precheck']['status'] for r in outcomes if r['id'] == label), '—')
        fast = targets['FAST']
        md.append(f'| {label} | {pre} | {targets["ChatGPTAPI"]["status"]} | '
            f'{fast["api"]["status"]} | {(fast.get("download") or {}).get("status", "未测")} | {targets["TikTokTrace"]["status"]} |')
    (root / 'summary.md').write_text('\n'.join(md) + '\n')


if __name__ == '__main__':
    main()
