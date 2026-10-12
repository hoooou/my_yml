"""Compare failed HTTPS proxies in a persistent and freshly started core."""
import argparse
import concurrent.futures as futures
import json
from pathlib import Path
import subprocess
import time

import yaml
import app_tls
from mobile_pilot import check_site, SITES
import select_nodes as s
import stability as st
import continuous_stability as cs


def candidates(report, snapshots):
    available = {}
    for config, previous in snapshots:
        by_name = {node['name']: node for node in config['proxies']}
        for row in previous['nodes']:
            if row.get('name') in by_name:
                available.setdefault(row['id'], {**by_name[row['name']], 'name': row['id']})
    collapsed, http_controls, other_controls = [], [], []
    for row in report['nodes']:
        node = available.get(row['id'])
        attempts = (row.get('stability') or {}).get('attempts', [])
        if not node or len(attempts) != st.ROUNDS:
            continue
        first_ok = st.round_passed(attempts[0])
        second_ok = st.round_passed(attempts[1])
        if node['type'] == 'http' and first_ok and not second_ok:
            collapsed.append(row)
        elif st.passed(row.get('stability')):
            (http_controls if node['type'] == 'http' else other_controls).append(row)
    chosen = [(r, 'collapsed_HTTPS') for r in collapsed[:8]]
    chosen += [(r, 'passed_HTTP_control') for r in http_controls[:2]]
    chosen += [(r, 'passed_other_protocol_control') for r in other_controls[:2]]
    return chosen, available


def batch_candidates(report, bundle):
    """Use the failed batch's real definitions, including never-published nodes."""
    mapping = {n['name']: n for n in bundle['nodes']}
    failed, http_controls, other_controls = [], [], []
    for row in report['nodes']:
        node = mapping.get(row['id'])
        result = row.get('stability') or {}
        if not node or not (cs.valid_evidence(result) if result.get('version') in (2, 3)
                            else len(result.get('attempts', [])) == st.ROUNDS):
            continue
        if node['type'] == 'http' and not st.passed(result):
            failed.append(row)
        elif st.passed(result):
            (http_controls if node['type'] == 'http' else other_controls).append(row)
    # Spread failing samples across observed countries before filling the cap.
    failed.sort(key=lambda row: not (
        any(st.round_passed(x) for x in row['stability']['attempts'][:8])
        and all(x['sites']['Google204'].get('status') == 'failed'
                for x in row['stability']['attempts'][-3:])))
    spread, seen = [], set()
    for row in failed:
        cc = (row.get('exit') or {}).get('country_code')
        if cc not in seen:
            spread.append(row); seen.add(cc)
    spread += [r for r in failed if r not in spread]
    return ([(r, 'failed_HTTPS') for r in spread[:8]]
            + [(r, 'passed_HTTP_control') for r in http_controls[:2]]
            + [(r, 'passed_other_protocol_control') for r in other_controls[:2]]), mapping


def curl_204(port, target_url=None, method='GET'):
    """Independent HTTP client, verified HTTPS, six-second diagnostic only."""
    import certifi
    target_url = target_url or SITES['Google204']
    if target_url not in (SITES['Google204'], 'https://cp.cloudflare.com/') or method not in ('GET', 'HEAD'):
        raise ValueError('Unsupported diagnostic target or method')
    command = ['curl', '--disable', '--silent', '--show-error', '--http1.1',
               '--proto', '=https', '--cacert', certifi.where(), '--noproxy', '',
               '--proxy', f'http://127.0.0.1:{port}', '--connect-timeout', '5',
               '--max-time', '6', '--max-filesize', '1024', '--output', '/dev/null',
               '--write-out', '%{json}', target_url]
    if method == 'HEAD':
        command.insert(2, '--head')
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=9)
        info = json.loads(proc.stdout)
        good = (proc.returncode == 0 and info['http_code'] == 204
                and info['ssl_verify_result'] == 0 and info['num_redirects'] == 0
                and info['url_effective'] == target_url and info['size_download'] == 0
                and 0 < info['time_total'] <= 6)
        return {'status': 'passed' if good else 'failed', 'url': target_url, 'method': method,
                'curl_exit_code': proc.returncode,
                'http_status': info['http_code'], 'ssl_verify_result': info['ssl_verify_result'],
                'elapsed_ms': round(info['time_total'] * 1000, 1),
                'connect_ms': round(info['time_connect'] * 1000, 1),
                'tls_ready_ms': round(info['time_appconnect'] * 1000, 1),
                'first_byte_ms': round(info['time_starttransfer'] * 1000, 1)}
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        return {'status': 'failed', 'error_type': 'diagnostic_tool_error'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--bundle')
    parser.add_argument('--report')
    parser.add_argument('--observe-seconds', type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.observe_seconds <= 240:
        parser.error('--observe-seconds must be between 0 and 240')
    if bool(args.bundle) != bool(args.report):
        parser.error('--bundle and --report must be supplied together')
    binary = str(Path(args.mihomo).resolve())
    root = Path('.node-work/stability-diagnostics').resolve()
    root.mkdir(parents=True, exist_ok=True)
    report = json.loads(Path(args.report or '连通性报告.json').read_text())
    refs = []
    if args.bundle:
        chosen, mapping = batch_candidates(report, json.loads(Path(args.bundle).read_text()))
    else:
        refs = subprocess.check_output(['git', 'log', '-2', '--format=%H', '--', '优选配置.yaml'], text=True).splitlines()
        snapshots = [(yaml.safe_load(subprocess.check_output(['git', 'show', ref + ':优选配置.yaml'], text=True)),
                      json.loads(subprocess.check_output(['git', 'show', ref + ':连通性报告.json'], text=True))) for ref in refs]
        chosen, mapping = candidates(report, snapshots)
    if not chosen:
        raise RuntimeError('没有可用的小样本历史定义')
    records = [r for r, _ in chosen]
    listeners, ports = s.make_listeners(records)
    output = {'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds'),
              'scope': 'small_sample_no_subscription_changes', 'source_refs': refs,
              'node_count': len(chosen), 'workers': 4,
              'nodes': [{'id': r['id'], 'category': kind, 'protocol': mapping[r['id']]['type'], 'samples': {}} for r, kind in chosen],
              'controls': {}, 'core_health': {}, 'extra_probes': {},
              'original_report_updated_at': report['updated_at'],
              'selection_criteria_changed': False}
    output['minimum_persistent_observation_seconds'] = args.observe_seconds
    by_id = {r['id']: r for r in output['nodes']}
    origin = time.monotonic()
    def extra(port):
        return {'requests_204_connect5_read2': check_site(port, 'Google204', SITES['Google204'], timeout=(5, 2)),
                'curl_204_total6': curl_204(port),
                'curl_204_HEAD_total6': curl_204(port, method='HEAD'),
                'curl_cloudflare_204_total6': curl_204(port, 'https://cp.cloudflare.com/'),
                'independent_Android_TLS': app_tls.probe(port, st.TLS_HOST)}
    def measure(label, number, core, extra_checks=True):
        output['controls'][label] = st.sample_control(number, origin)
        with futures.ThreadPoolExecutor(max_workers=4) as pool:
            jobs = {pool.submit(st.sample_node, ports[r['id']], number, origin): r['id'] for r in records}
            for job in futures.as_completed(jobs):
                by_id[jobs[job]]['samples'][label] = job.result()
            if extra_checks:
                diagnostics = {pool.submit(extra, ports[r['id']]): r['id'] for r in records}
                output['extra_probes'][label] = {diagnostics[job]: job.result() for job in futures.as_completed(diagnostics)}
        print(label, {kind: sum(st.round_passed(by_id[r['id']]['samples'][label]) for r, k in chosen if k == kind)
                      for kind in sorted({k for _, k in chosen})}, flush=True)
        output['core_health'][label] = st.core_health(core, root)
        (root / 'results.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n')
    with s.Core(binary, root, [mapping[r['id']] for r in records], listeners) as core:
        persistent_start = time.monotonic()
        measure('initial_core', 1, core)
        time.sleep(30)
        measure('same_core_after_idle', 2, core)
        number = 3
        while time.monotonic() - persistent_start < args.observe_seconds:
            time.sleep(max(0, min(15, args.observe_seconds - (time.monotonic() - persistent_start))))
            measure('persistent_round_' + str(number), number, core, extra_checks=False)
            number += 1
        if args.observe_seconds:
            measure('same_core_after_observation', number, core)
    # Independent core process, same node definitions and isolated listener ports.
    with s.Core(binary, root, [mapping[r['id']] for r in records], listeners) as core:
        measure('fresh_core', 3, core)
    # Swap only the initial connection timeout on a separate cold core.
    with s.Core(binary, root, [mapping[r['id']] for r in records], listeners) as core:
        output['controls']['fresh_core_connect5_first'] = st.sample_control(4, origin)
        with futures.ThreadPoolExecutor(max_workers=4) as pool:
            jobs = {pool.submit(check_site, ports[r['id']], 'Google204', SITES['Google204'], (5, 2)): r['id'] for r in records}
            output['extra_probes']['fresh_core_connect5_first'] = {jobs[job]: job.result() for job in futures.as_completed(jobs)}
        output['core_health']['fresh_core_connect5_first'] = st.core_health(core, root)
    (root / 'results.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n')
    print('诊断完成；未修改订阅，诊断结果不代替全量稳定性证据', flush=True)


if __name__ == '__main__':
    main()
