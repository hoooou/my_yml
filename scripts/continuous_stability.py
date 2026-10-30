"""Independent, scheduled observations while the main screening job runs.

Successful-request percentiles and failed-round frequency are separate metrics.
No authenticated app/session or domestic-mobile throughput is claimed.
"""
import concurrent.futures as futures
import heapq
import json
import math
import os
from pathlib import Path
import re
import random
import statistics
import time

import select_nodes as s
import stability as legacy
import quality_policy as qp

VERSION = 5
VERSIONS = (2, 3, 4, 5)
# observe 只跟随主筛选，不再要求独立的时间窗口
MIN_WINDOW_SECONDS = 0
IDLE_MIN = 3
IDLE_MAX = 10
PEER_POLL_SECONDS = 30
STANDALONE_SECONDS = 600
WORKERS = 8
# 主流程完成（flag 置位）后，只允许再跑这么久给每个节点补最后一轮采样；
# 之前没有 flag 之前不计时，靠作业超时兜底，不再设整轮预算。
TAIL_SECONDS = 30 * 60
PEER_JOB = '两轮上行及负载后SSL'


def settings(version=VERSION):
    policy = {**legacy.settings(), 'version': VERSION, 'rounds': None,
            'minimum_rounds': None, 'minimum_start_interval_seconds': None,
            'random_idle_seconds_range': [IDLE_MIN, IDLE_MAX],
            'minimum_idle_seconds_between_rounds': None, 'node_workers': WORKERS,
            'requires_all_rounds': False, 'minimum_success_rate': .90,
            'parallel_independent_runner': True, 'scope': 'domestic_TCP_passed',
            'observes_until': 'uplink_job_completed_and_one_sample_after_completion',
            'maximum_tail_seconds': TAIL_SECONDS, 'percentiles': 'nearest_rank_successful_requests_per_target',
            'continuous_latency_hard_caps': False, 'explicit_certificate_error_rejects': True,
            'minimum_window_seconds': MIN_WINDOW_SECONDS, 'connection_modes': ['fresh', 'pooled_https'],
            'short_circuit_after_failure': False, 'p99_minimum_success_samples': 100}
    policy['version'] = version
    if version in (2, 3, 4):
        policy.update(minimum_window_seconds=0, scope='domestic_TCP_and_3MB_upload_passed')
    if version in (2, 3):
        policy.update(version=version, minimum_rounds=20 if version == 2 else None,
                      minimum_start_interval_seconds=30 if version == 2 else 15)
        policy.pop('random_idle_seconds_range')
    return policy


def certificate_error(sample):
    items = list((sample.get('sites') or {}).values()) + [sample.get('android_tls') or {}]
    return any(x.get('tls_error_kind') == 'certificate_verification_failed'
               or x.get('error_type') == 'certificate_verification_failed' for x in items + [sample.get('connection_reuse') or {}])


def round_passed(sample, version=VERSION):
    return legacy.round_passed(sample) and (version != VERSION or legacy.page_probe_passed(
        'Google204', sample.get('connection_reuse') or {}))


def valid_evidence(result):
    if not isinstance(result, dict) or result.get('version') not in VERSIONS:
        return False
    attempts = result.get('attempts') or []
    cutoff = result.get('peer_completed_offset_seconds')
    interval = 30 if result['version'] == 2 else 15 if result['version'] == 3 else IDLE_MIN
    enough = len(attempts) >= 20 if result['version'] == 2 else bool(attempts)
    if not enough or not legacy.finite(cutoff) or cutoff < 0:
        return False
    last_start, last_end = None, None
    for number, sample in enumerate(attempts, 1):
        start, end = sample.get('started_offset_seconds'), sample.get('finished_offset_seconds')
        if (sample.get('round') != number or not legacy.finite(start) or not legacy.finite(end)
                or not 0 <= start <= end or set(sample.get('sites') or {}) != set(legacy.TARGETS)
                or not isinstance(sample.get('android_tls'), dict)
                or (result['version'] == VERSION and not isinstance(sample.get('connection_reuse'), dict))
                or (last_start is not None and ((start - last_end if result['version'] in (4, VERSION) else start - last_start) < interval - .001 or start < last_end))):
            return False
        last_start, last_end = start, end
    return (last_start >= cutoff and (result['version'] != VERSION or
        last_end - attempts[0]['started_offset_seconds'] >= MIN_WINDOW_SECONDS))


def passed(result):
    return (isinstance(result, dict) and result.get('status') == 'passed' and valid_evidence(result)
            and not any(certificate_error(x) for x in result['attempts'])
            and (result['version'] != VERSION or not any(qp.tls_errors(x) for x in result['attempts']))
            and sum(round_passed(x, result['version']) for x in result['attempts']) * 10 >= len(result['attempts']) * 9)


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(fraction * len(values)) - 1)] if values else None


def metrics(result):
    attempts = result.get('attempts') or []
    version = result.get('version', 4)
    good = sum(round_passed(x, version) for x in attempts)
    streak, worst = 0, 0
    failure_start, recovery = None, 0
    for item in attempts:
        ok = round_passed(item, version)
        if not ok and failure_start is None:
            failure_start = item.get('started_offset_seconds', 0)
        if ok and failure_start is not None:
            recovery = max(recovery, item.get('finished_offset_seconds', 0) - failure_start)
            failure_start = None
        streak = 0 if ok else streak + 1
        worst = max(worst, streak)
    targets = {}
    for label in legacy.TARGETS:
        values = [x['sites'][label]['elapsed_ms'] for x in attempts
                  if (x.get('sites', {}).get(label) or {}).get('status') == 'passed'
                  and legacy.finite(x['sites'][label].get('elapsed_ms'))
                  and 0 <= x['sites'][label]['elapsed_ms'] <= 5000]
        if values:
            targets[label] = {'sample_count': len(values), 'median_ms': statistics.median(values),
                              'p95_ms': percentile(values, .95), 'p99_ms': percentile(values, .99) if version != VERSION or len(values) >= 100 else None,
                              'p95_minus_p50_ms': percentile(values, .95) - statistics.median(values),
                              'iqr_ms': percentile(values, .75) - percentile(values, .25)}
    requests = [p for a in attempts for p in list(a.get('sites', {}).values()) +
                [a.get('android_tls') or {}, a.get('connection_reuse') or {}] if p.get('status') not in (None, 'skipped')]
    reused = [a['connection_reuse'] for a in attempts if a.get('connection_reuse')]
    if failure_start is not None and attempts:
        recovery = max(recovery, attempts[-1].get('finished_offset_seconds', 0) - failure_start)
    return {'round_count': len(attempts), 'passed_count': good,
            'success_rate': good / len(attempts) if attempts else 0,
            'request_count': len(requests), 'request_success_count': sum(p.get('status') in ('passed', 'verification_required') for p in requests),
            'skipped_request_count': sum(p.get('status') == 'skipped' for a in attempts for p in a.get('sites', {}).values()),
            'reused_request_count': len(reused), 'reused_success_count': sum(legacy.page_probe_passed('Google204', p) for p in reused),
            'maximum_recovery_seconds': round(recovery, 3), 'unrecovered_at_end': failure_start is not None,
            'maximum_consecutive_failures': worst, 'targets': targets}


def core_metrics(result):
    return {label: {**item, 'tail_ms': item['p95_ms'], 'jitter_ms': item['iqr_ms']}
            for label, item in metrics(result)['targets'].items() if label in ('Google', 'YouTube')}


def summarize(attempts, cutoff=None, version=VERSION):
    result = {'version': version, 'attempts': attempts, **metrics({'version': version, 'attempts': attempts}),
              'peer_completed_offset_seconds': cutoff,
              'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds')}
    result['status'] = 'passed'
    result['status'] = 'incomplete' if not valid_evidence(result) else 'passed' if passed(result) else 'failed'
    result['failures'] = [{'round': x['round'], 'target': k,
        'status': item.get('status'), 'reason': item.get('reason', item.get('error_type'))}
        for x in attempts for k, item in list((x.get('sites') or {}).items()) + [('Android SSL', x.get('android_tls') or {})]
        if item.get('status') != 'skipped' and (not legacy.tls_passed(item) if k == 'Android SSL' else
            not legacy.page_probe_passed(k, item))]
    if version == VERSION:
        result['failures'] += [{'round': x['round'], 'target': 'pooled Google204',
            'status': x['connection_reuse'].get('status'),
            'reason': x['connection_reuse'].get('reason', x['connection_reuse'].get('error_type'))}
            for x in attempts if not legacy.page_probe_passed('Google204', x.get('connection_reuse') or {})]
    result['window_seconds'] = attempts[-1]['finished_offset_seconds'] - attempts[0]['started_offset_seconds'] if attempts else 0
    return result


def control_passed(control):
    page = (control.get('sites') or {}).get('Google204') or {}
    return (page.get('status') == 'passed' and legacy.finite(page.get('elapsed_ms'))
            and 0 <= page['elapsed_ms'] <= 5000 and legacy.tls_passed(control.get('android_tls')))


class PeerJob:
    """Read this attempt's upstream jobs, never a cached/historical run."""
    def __init__(self):
        self.repo, self.run = os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_RUN_ID']
        self.attempt = int(os.environ['GITHUB_RUN_ATTEMPT'])
        self.token = os.environ['GH_TOKEN']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', self.repo) or not self.run.isdigit():
            raise ValueError('无效运行标识')

    def __call__(self):
        response = s.requests.get(
            f'https://api.github.com/repos/{self.repo}/actions/runs/{self.run}/attempts/{self.attempt}/jobs',
            headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json'},
            params={'per_page': 100}, timeout=(5, 10))
        response.raise_for_status()
        jobs = response.json()['jobs']
        # An upstream failure must terminate observers even if the final job is not yet created.
        for job in jobs:
            if (job['name'].startswith('网站、TLS与下载') or job['name'] == PEER_JOB) and job['status'] == 'completed' and job['conclusion'] != 'success':
                raise RuntimeError('主筛选任务失败，停止观察并保留原订阅')
        peer = [x for x in jobs if x['name'] == PEER_JOB]
        if len(peer) > 1:
            raise RuntimeError('主筛选任务标识重复')
        return bool(peer and peer[0]['status'] == 'completed' and peer[0]['conclusion'] == 'success')


def schedule(ids, probe, peer, control, checkpoint, clock=time.monotonic, sleep=time.sleep, workers=WORKERS):
    """A due-time heap keeps sleeping candidates from occupying worker slots."""
    origin = clock()
    attempts = {id: [] for id in ids}
    due = [(origin, id) for id in ids]
    heapq.heapify(due)
    running, cutoff, cutoff_at = {}, None, None
    next_control = next_peer = origin
    try:
        with futures.ThreadPoolExecutor(max_workers=workers) as pool:
            while due or running:
                now = clock()
                if cutoff_at is not None and now - cutoff_at > TAIL_SECONDS:
                    raise RuntimeError('主流程完成后收尾超时，保留原订阅')
                if now >= next_peer and cutoff is None:
                    if peer():
                        cutoff = clock() - origin
                        cutoff_at = clock()
                    next_peer = clock() + PEER_POLL_SECONDS
                if now >= next_control:
                    control(len(attempts), origin)
                    checkpoint(attempts, cutoff, False)
                    next_control = clock() + 60
                while due and due[0][0] <= clock() and len(running) < workers:
                    _, id = heapq.heappop(due)
                    running[pool.submit(probe, id, len(attempts[id]) + 1, origin)] = id
                done = [job for job in running if job.done()]
                for job in done:
                    id = running.pop(job)
                    item = job.result()
                    attempts[id].append(item)
                    if not (cutoff is not None and item['started_offset_seconds'] >= cutoff
                            and item['finished_offset_seconds'] - attempts[id][0]['started_offset_seconds'] >= MIN_WINDOW_SECONDS):
                        idle = random.uniform(IDLE_MIN, IDLE_MAX)
                        item['next_idle_seconds'] = idle
                        heapq.heappush(due, (origin + item['finished_offset_seconds'] + idle, id))
                if due or running:
                    # Poll only active futures briefly; otherwise sleep to the next due/control/API tick.
                    if running:
                        futures.wait(running, timeout=.1, return_when=futures.FIRST_COMPLETED)
                    else:
                        sleep(max(.001, min(due[0][0], next_control, next_peer if cutoff is None else math.inf) - clock()))
    except Exception:
        checkpoint(attempts, cutoff, False)
        raise

    if ids:
        control(len(attempts), origin)
    return checkpoint(attempts, cutoff, True)


def observe(records, mapping, binary, root, peer=None):
    root = Path(root); root.mkdir(parents=True, exist_ok=True)
    listeners, ports = s.make_listeners(records)
    controls, health = [], []
    policy = settings()
    if peer is not None:
        policy.update(parallel_independent_runner=False, observes_until='standalone_600_second_window',
                      standalone_window_seconds=STANDALONE_SECONDS, scope='eligible_pool_after_upload')
        previous_peer, deadline = peer, time.monotonic() + STANDALONE_SECONDS
        peer = lambda: previous_peer() and time.monotonic() >= deadline
    peer = (peer or PeerJob()) if records else (lambda: True)
    def snapshot(attempts, cutoff, complete):
        results = {id: summarize(items, cutoff) for id, items in attempts.items()}
        result = {'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds'),
                  'settings': policy, 'node_count': len(records), 'complete': complete,
                  'scope': policy['scope'],
                  'controls_valid': bool(complete and all(control_passed(x) for x in controls)
                                         and all(legacy.core_healthy(x) for x in health)),
                  'controls': controls, 'core_health': health,
                  'nodes': [{'id': id, 'stability': item} for id, item in results.items()]}
        temp = root / 'stability-results.tmp'
        temp.write_text(json.dumps(result, ensure_ascii=False, indent=2))
        temp.replace(root / 'stability-results.json')
        rounds = [len(x) for x in attempts.values()]
        print(f'持续稳定性：{len(records)}节点，轮数{min(rounds, default=0)}～{max(rounds, default=0)}，主流程已完成{cutoff is not None}', flush=True)
        return result
    if not records:
        return snapshot({}, None, True)
    snapshot({r['id']: [] for r in records}, None, False)
    with s.Core(binary, root, [mapping[r['id']] for r in records], listeners) as core:
        clients = {r['id']: s.session() for r in records}
        def control(number, origin):
            started = time.monotonic() - origin
            sample = legacy.sample_control(len(controls) + 1, origin)
            state = legacy.core_health(core, root)
            sample.update(started_offset_seconds=started, finished_offset_seconds=time.monotonic() - origin)
            controls.append(sample); health.append(state)
            if not control_passed(sample) or not legacy.core_healthy(state):
                raise RuntimeError('独立观察环境对照异常，保留原订阅')
        def sample(id, number, origin):
            start = time.monotonic() - origin
            started_at = s.datetime.now(s.TZ).isoformat(timespec='seconds')
            sites = {label: legacy.check_site(ports[id], label, legacy.SITES[label]) for label in legacy.TARGETS}
            tls = legacy.app_tls.probe(ports[id], legacy.TLS_HOST)
            reused = legacy.check_site(ports[id], 'Google204', legacy.SITES['Google204'], client=clients[id])
            return {'round': number, 'started_at': started_at,
                    'started_offset_seconds': round(start, 4), 'finished_offset_seconds': round(time.monotonic() - origin, 4),
                    'sites': sites, 'android_tls': tls, 'connection_reuse': reused}
        try:
            return schedule([r['id'] for r in records], sample, peer, control, snapshot)
        finally:
            for client in clients.values():
                client.close()


def merge(bundle, parts, records, count, shard_nodes):
    if len(parts) != count or {p.get('index') for p in parts} != set(range(count)):
        raise ValueError('持续观察缺少分片')
    modern = (bundle.get('stability_policy') or {}).get('version') == VERSION
    eligible = {r['id'] for r in records if r['entry']['status'] == 'passed'
                and (modern or (r.get('upload_precheck') or {}).get('status') == 'passed')}
    combined, diagnostics = {}, []
    for part in parts:
        if part.get('bundle_id') != bundle['id'] or part.get('count') != count:
            raise ValueError('持续观察批次或分片不一致')
        diagnostic = part.get('diagnostic') or {}
        expected_version = (bundle.get('stability_policy') or {}).get('version', VERSION)
        if (diagnostic.get('settings') or {}).get('version') != expected_version:
            raise ValueError('持续观察策略版本与本轮输入不一致')
        expected = {n['name'] for n in shard_nodes(bundle['nodes'], part['index'], count)} & eligible
        rows = diagnostic.get('nodes') or []
        if (len(rows) != len(expected) or {r['id'] for r in rows} != expected
                or diagnostic.get('node_count') != len(expected)
                or diagnostic.get('complete') is not True or diagnostic.get('controls_valid') is not True):
            raise ValueError('持续观察缺失、重复或未完成')
        if expected and (not diagnostic.get('controls') or not diagnostic.get('core_health')
                or not all(control_passed(x) for x in diagnostic['controls'])
                or not all(legacy.core_healthy(x) for x in diagnostic['core_health'])):
            raise ValueError('持续观察缺少有效环境对照')
        if expected:
            checks = diagnostic['controls']
            end = max(r['stability']['attempts'][-1]['finished_offset_seconds'] for r in rows if r.get('stability', {}).get('attempts')) if all(r.get('stability', {}).get('attempts') for r in rows) else math.inf
            if (len(checks) < 2 or any(not legacy.finite(c.get('started_offset_seconds'))
                    or not legacy.finite(c.get('finished_offset_seconds'))
                    or not 0 <= c['started_offset_seconds'] <= c['finished_offset_seconds'] for c in checks)
                    or checks[0]['started_offset_seconds'] > 30
                    or checks[-1]['finished_offset_seconds'] + .001 < end
                    or any(b['started_offset_seconds'] < a['finished_offset_seconds']
                        or b['started_offset_seconds'] - a['finished_offset_seconds'] > 90
                        for a, b in zip(checks, checks[1:]))):
                raise ValueError('持续观察环境对照未覆盖检测窗口')
        for row in rows:
            if (row.get('stability') or {}).get('version') != expected_version or not valid_evidence(row.get('stability')):
                raise ValueError('持续观察缺少有效样本、时间间隔或主流程结束后的复测')
            combined[row['id']] = summarize(row['stability']['attempts'], row['stability']['peer_completed_offset_seconds'], version=expected_version)
            if row['stability'].get('updated_at'):
                combined[row['id']]['updated_at'] = row['stability']['updated_at']
        diagnostics.append(diagnostic)
    for record in records:
        if record['id'] in combined:
            record['stability'] = combined[record['id']]
    return {'updated_at': max((d['updated_at'] for d in diagnostics), default=None),
            'settings': settings((bundle.get('stability_policy') or {}).get('version', VERSION)), 'scope': 'domestic_TCP_passed' if modern else 'domestic_TCP_and_3MB_upload_passed',
            'node_count': len(combined), 'complete': True, 'controls_valid': True,
            'nodes': [{'id': id, 'stability': item} for id, item in combined.items()],
            'shards': diagnostics}
