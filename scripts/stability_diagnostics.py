"""Compare failed HTTPS proxies in a persistent and freshly started core."""
import argparse
import concurrent.futures as futures
import json
from pathlib import Path
import subprocess
import time

import yaml
import select_nodes as s
import stability as st


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mihomo', required=True)
    args = parser.parse_args()
    binary = str(Path(args.mihomo).resolve())
    root = Path('.node-work/stability-diagnostics').resolve()
    root.mkdir(parents=True, exist_ok=True)
    report = json.loads(Path('连通性报告.json').read_text())
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
              'controls': {}, 'core_health': {}}
    by_id = {r['id']: r for r in output['nodes']}
    origin = time.monotonic()
    def measure(label, number, core):
        output['controls'][label] = st.sample_control(number, origin)
        with futures.ThreadPoolExecutor(max_workers=4) as pool:
            jobs = {pool.submit(st.sample_node, ports[r['id']], number, origin): r['id'] for r in records}
            for job in futures.as_completed(jobs):
                by_id[jobs[job]]['samples'][label] = job.result()
        print(label, {kind: sum(st.round_passed(by_id[r['id']]['samples'][label]) for r, k in chosen if k == kind)
                      for kind in sorted({k for _, k in chosen})}, flush=True)
        health = {'process_alive': core.process.poll() is None}
        try:
            health['open_connections'] = len(core.get('/connections').get('connections') or [])
            health['api_available'] = True
        except Exception as error:
            health['api_available'] = False
            health['api_error_type'] = type(error).__name__
        fd_path = Path('/proc') / str(core.process.pid) / 'fd'
        if fd_path.exists():
            health['open_file_descriptors'] = len(list(fd_path.iterdir()))
        # Never expose raw core logs, which can include sensitive node details.
        log = (root / 'core.log').read_text(errors='replace')
        health['file_limit_errors'] = log.lower().count('too many open files')
        output['core_health'][label] = health
        (root / 'results.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n')
    with s.Core(binary, root, [mapping[r['id']] for r in records], listeners) as core:
        measure('initial_core', 1, core)
        time.sleep(30)
        measure('same_core_after_idle', 2, core)
    # Independent core process, same node definitions and isolated listener ports.
    with s.Core(binary, root, [mapping[r['id']] for r in records], listeners) as core:
        measure('fresh_core', 3, core)
    print('诊断完成；未修改订阅，结果不冒充五轮稳定性通过', flush=True)


if __name__ == '__main__':
    main()
