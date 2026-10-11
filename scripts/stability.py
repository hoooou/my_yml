"""Time-spaced, low-concurrency probes of the final eligible pool.

These anonymous requests do not emulate authenticated ChatGPT conversations.
An exit-IP change is diagnostic information, never a rejection criterion.
"""
import concurrent.futures as futures
import json
import math
from pathlib import Path
import statistics
import time

import app_tls
from mobile_pilot import check_site, SITES
import select_nodes as s

VERSION = 1
ROUNDS = 5
GAP_SECONDS = 30
WORKERS = 4
TARGETS = ('Google204', 'Google', 'YouTube', 'ChatGPTTrace')
TLS_HOST = 'android.chat.openai.com'


def settings():
    return {'version': VERSION, 'rounds': ROUNDS, 'minimum_idle_seconds_between_rounds': GAP_SECONDS,
            'node_workers': WORKERS, 'requests_per_node_in_parallel': 1,
            'targets': {k: SITES[k] for k in TARGETS}, 'tls_hostname': TLS_HOST,
            'requires_all_rounds': True, 'exit_ip_change_rejects': False,
            'authenticated_conversation_tested': False, 'automatic_switching': False}


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def tls_passed(item):
    return (isinstance(item, dict) and item.get('status') == 'passed'
            and item.get('hostname') == TLS_HOST
            and item.get('tls_version') in ('TLSv1.2', 'TLSv1.3')
            and all(item.get(k) is True for k in ('chain_verified', 'hostname_verified', 'validity_verified'))
            and finite(item.get('elapsed_ms')) and 0 <= item['elapsed_ms'] <= app_tls.BUDGET_SECONDS * 1000)


def round_passed(sample):
    sites = sample.get('sites') or {}
    return (set(sites) == set(TARGETS) and all(
        sites[label].get('status') == 'passed' and finite(sites[label].get('elapsed_ms'))
        and 0 <= sites[label]['elapsed_ms'] <= 5000 for label in TARGETS)
        and tls_passed(sample.get('android_tls')))


def evidence_passed(result):
    if not isinstance(result, dict) or result.get('version') != VERSION:
        return False
    samples = result.get('attempts') or []
    if len(samples) != ROUNDS:
        return False
    previous_end = None
    for i, sample in enumerate(samples):
        start, end = sample.get('started_offset_seconds'), sample.get('finished_offset_seconds')
        if (sample.get('round') != i + 1 or not finite(start) or not finite(end)
                or not 0 <= start <= end or not round_passed(sample)
                or (previous_end is not None and start - previous_end < GAP_SECONDS - .001)):
            return False
        previous_end = end
    return True


def passed(result):
    return isinstance(result, dict) and result.get('status') == 'passed' and evidence_passed(result)


def core_metrics(result):
    """Derive latency from actual samples rather than trusting cached summaries."""
    values = {label: [x['sites'][label]['elapsed_ms'] for x in result['attempts']] for label in ('Google', 'YouTube')}
    return {label: {'median_ms': statistics.median(items), 'tail_ms': max(items),
                    'jitter_ms': max(items) - min(items)} for label, items in values.items()}


def quality_passed(result, median_limit, tail_limit, jitter_limit):
    return passed(result) and all(item['median_ms'] <= median_limit
        and item['tail_ms'] <= tail_limit and item['jitter_ms'] <= jitter_limit
        for item in core_metrics(result).values())


def summarize(attempts):
    result = {'version': VERSION, 'attempts': attempts, 'round_count': len(attempts),
              'passed_count': sum(round_passed(x) for x in attempts),
              'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds')}
    result['status'] = 'passed' if evidence_passed(result) else 'failed'
    result['failures'] = [{'round': sample['round'], 'target': label,
        'status': sample['sites'][label].get('status'),
        'reason': sample['sites'][label].get('reason')}
        for sample in attempts for label in TARGETS
        if sample['sites'][label].get('status') != 'passed'
        or not finite(sample['sites'][label].get('elapsed_ms'))
        or not 0 <= sample['sites'][label]['elapsed_ms'] <= 5000]
    result['failures'] += [{'round': sample['round'], 'target': TLS_HOST,
        'status': sample['android_tls'].get('status'),
        'reason': sample['android_tls'].get('error_type', 'unverified_or_late_TLS')}
        for sample in attempts if not tls_passed(sample['android_tls'])]
    result['core_median_ms'] = {label: statistics.median(
        [x['sites'][label]['elapsed_ms'] for x in attempts
         if x['sites'][label].get('status') == 'passed' and finite(x['sites'][label].get('elapsed_ms'))])
        for label in ('Google', 'YouTube')
        if any(x['sites'][label].get('status') == 'passed' and finite(x['sites'][label].get('elapsed_ms')) for x in attempts)}
    result['observed_exit_ip_count'] = len({x['sites']['ChatGPTTrace']['exit_ip'] for x in attempts
        if x['sites']['ChatGPTTrace'].get('exit_ip')})
    result['window_seconds'] = (attempts[-1]['finished_offset_seconds'] - attempts[0]['started_offset_seconds']) if attempts else 0
    return result


def sample_node(port, number, origin):
    started = time.monotonic()
    started_at = s.datetime.now(s.TZ).isoformat(timespec='seconds')
    sites = {label: check_site(port, label, SITES[label]) for label in TARGETS}
    tls = app_tls.probe(port, TLS_HOST)
    return {'round': number, 'started_at': started_at,
            'started_offset_seconds': round(started - origin, 4),
            'finished_offset_seconds': round(time.monotonic() - origin, 4),
            'sites': sites, 'android_tls': tls}


def sample_control(number, origin):
    # The direct connection is a runner-health control, not another candidate.
    return {'round': number, 'sites': {'Google204': check_site(None, 'Google204', SITES['Google204'])},
            'android_tls': app_tls.probe(None, TLS_HOST)}


def wait_between_rounds(previous_end, clock=None, sleep=None):
    clock, sleep = clock or time.monotonic, sleep or time.sleep
    while clock() - previous_end < GAP_SECONDS:
        sleep(GAP_SECONDS - (clock() - previous_end))


def recheck(records, mapping, binary, root):
    """Only callers' eligible candidates; reports contain no node credentials."""
    if not records:
        return {'settings': settings(), 'node_count': 0, 'controls': [], 'nodes': []}
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    listeners, ports = s.make_listeners(records)
    origin = time.monotonic()
    samples = {r['id']: [] for r in records}
    controls = []
    with s.Core(binary, root, [mapping[r['id']] for r in records], listeners):
        with futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for number in range(1, ROUNDS + 1):
                if number > 1:
                    wait_between_rounds(previous_end)
                control = sample_control(number, origin)
                controls.append(control)
                jobs = {pool.submit(sample_node, ports[r['id']], number, origin): r['id'] for r in records}
                for job in futures.as_completed(jobs):
                    samples[jobs[job]].append(job.result())
                previous_end = time.monotonic()
                count = sum(all(round_passed(x) for x in samples[r['id']]) for r in records)
                print(f'间隔稳定性 {number}/{ROUNDS}：{len(records)}节点，目前全轮通过{count}；节点并发{WORKERS}', flush=True)
    # Direct Google/YT pages are recorded for comparison. Only direct 204 and
    # verified Android TLS are runner controls; a control outage aborts publication.
    control_ok = all(x['sites']['Google204'].get('status') == 'passed'
                     and tls_passed(x.get('android_tls')) for x in controls)
    results = {id: summarize(attempts) for id, attempts in samples.items()}
    diagnostic = {'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds'),
                  'settings': settings(), 'node_count': len(records), 'controls_valid': control_ok,
                  'controls': controls, 'nodes': [{'id': r['id'], 'previous_name': r.get('name'),
                      'stability': results[r['id']]} for r in records]}
    (root / 'stability-results.json').write_text(json.dumps(diagnostic, ensure_ascii=False, indent=2) + '\n')
    if not control_ok:
        raise RuntimeError('云端直连204或Android TLS对照异常，稳定性记录已保存；不据此淘汰或发布')
    for record in records:
        record['stability'] = results[record['id']]
    return diagnostic
