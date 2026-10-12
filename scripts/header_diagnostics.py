"""Paired cloud-only header audit of every daily destination; no publication."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path

from availability import summarize_rounds
import mobile_pilot as p
import select_nodes as s
from website_diagnostics import browser_probe

LABELS = tuple(p.OVERSEAS_SITES) + tuple(p.CONNECTIVITY_SITES)


def choose_samples(bundle, report, limit=2):
    available = {x['name'] for x in bundle['nodes']}
    candidates = [r for r in report['nodes'] if r['id'] in available and r.get('websites')
                  and (r.get('precheck') or {}).get('status') == 'passed'
                  and (r.get('upload_precheck') or {}).get('status') == 'passed']
    candidates.sort(key=lambda r: (-sum(x.get('status') == 'passed' for x in r['websites'].values()), r['id']))
    selected, ips, countries = [], set(), set()
    for diverse in (True, False):
        for row in candidates:
            ip = (row.get('exit') or {}).get('exit_ip')
            cc = (row.get('exit') or {}).get('country_code')
            if row in selected or ip in ips or diverse and cc in countries:
                continue
            selected.append(row); ips.add(ip); countries.add(cc)
            if len(selected) == limit:
                return selected
    return selected


def accepted(label, sample):
    return sample.get('status') == 'passed' or p.confirmed_page_exception(label, sample)


def inspect(port, label):
    attempts = {'original': [], 'navigation': []}
    for round_number in range(3):
        # Alternate order to reduce a simple warm-up/order bias.
        order = ('original', 'navigation') if round_number % 2 == 0 else ('navigation', 'original')
        for kind in order:
            headers = {'User-Agent': p.WEB_USER_AGENT} if kind == 'original' else p.navigation_headers()
            attempts[kind].append(p.check_site(port, label, p.SITES[label], request_headers=headers))
    result = {'label': label, 'url': p.SITES[label], 'variants': {}}
    for kind, values in attempts.items():
        result['variants'][kind] = {'attempts': values, 'accepted_count': sum(accepted(label, x) for x in values),
                                   'summary': summarize_rounds([{label: x} for x in values], (label,))[label]}
    return result


def inspect_cohort(port, sample):
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda label: inspect(port, label), LABELS))
    changed = [r for r in results if r['label'] in p.PAGE_SITES
               and r['variants']['original']['accepted_count'] != r['variants']['navigation']['accepted_count']]
    # Ordinary browser evidence is supplemental; never relabel production requests.
    for item in changed[:4]:
        item['ordinary_browser'] = browser_probe(port, item['label'])
    return {'sample': sample, 'results': results}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Real header probes must run in GitHub Actions')
    root = Path('.node-work/website-diagnostics').resolve(); root.mkdir(parents=True, exist_ok=True)
    bundle = json.loads(Path(args.bundle).read_text())
    report = json.loads(Path(args.report).read_text())
    candidates = choose_samples(bundle, report, limit=12)
    if not candidates:
        raise RuntimeError('No mapped source samples')
    controls = {'before': p.check_site(None, 'Google204', p.SITES['Google204'])}
    mapping = {x['name']: x for x in bundle['nodes']}
    listeners, ports = s.make_listeners(candidates)
    cohorts = []
    preflights = []
    with s.Core(str(Path(args.mihomo).resolve()), root, [mapping[r['id']] for r in candidates], listeners):
        for row in candidates:
            port = ports[row['id']]
            control = [p.check_site(port, 'Google204', p.SITES['Google204']) for _ in range(3)]
            preflights.append({'sample': row['id'], 'attempts': control})
            if any(x.get('status') != 'passed' for x in control):
                print('样本目前204未全过，保留记录并换下一个：' + row['id'], flush=True)
                continue
            item = inspect_cohort(port, row['id'])
            item.update(country_code=(row.get('exit') or {}).get('country_code'), precheck=control,
                        postcheck=p.check_site(port, 'Google204', p.SITES['Google204']))
            cohorts.append(item)
            print('完整请求头对照完成：' + row['id'], flush=True)
            if len(cohorts) == 2:
                break
    cohorts.append(inspect_cohort(None, 'github-direct'))
    controls['after'] = p.check_site(None, 'Google204', p.SITES['Google204'])
    output = {'scope': 'readonly_all_daily_destinations', 'source_report_updated_at': report['updated_at'],
              'source_run': os.environ.get('GITHUB_RUN_ID'), 'targets': list(LABELS), 'rounds_per_variant': 3,
              'request_workers': 5, 'tls_verification': True, 'subscription_updated': False,
              'controls': controls, 'sample_preflights': preflights,
              'live_node_samples': len(cohorts) - 1, 'cohorts': cohorts}
    (root/'summary.json').write_text(json.dumps(output, ensure_ascii=False, indent=2)+'\n')
    columns = [c['sample'] for c in cohorts]
    rows = ['# 全站请求头对照', '', f'当前连通的{len(cohorts)-1}个节点及GitHub直连；同目标、每种请求头三轮、交替顺序。', '',
            '25个海外网页、ChatGPT API、204及两个trace，共29个目标；严格TLS、原页面识别和速度预算。', '',
            '| 网站／接口 | '+' | '.join(columns)+' |', '|---|'+'---|'*len(columns)]
    for label in LABELS:
        values = []
        for cohort in cohorts:
            item = next(x for x in cohort['results'] if x['label'] == label)
            values.append(str(item['variants']['original']['accepted_count'])+'/3 → '
                          +str(item['variants']['navigation']['accepted_count'])+'/3')
        rows.append('| '+label+' | '+' | '.join(values)+' |')
    rows += ['', '通过数量包含已确认CF验证及Reddit登录例外，不证明完整功能。API／204／trace使用导航头只作对照，不表示生产接口应发送HTML Accept。普通浏览器对部分差异另作诊断；结果不能替代三轮的响应质量预算。', '']
    (root/'summary.md').write_text('\n'.join(rows)+'\n')


if __name__ == '__main__':
    main()
