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
from mobile_pilot import check_site, SITES, confirmed_cloudflare_challenge
import select_nodes as s

VERSION = 1
ROUNDS = 5
GAP_SECONDS = 30
WORKERS = 4
TARGETS = ('Google204', 'Google', 'YouTube', 'ChatGPTTrace')
TLS_HOST = 'android.chat.openai.com'


def settings(records=None):
    if records and any((r.get('stability') or {}).get('version') in (2, 3) for r in records):
        import continuous_stability
        return continuous_stability.settings(max((r.get('stability') or {}).get('version', 1) for r in records))
    return {'version': VERSION, 'rounds': ROUNDS, 'minimum_idle_seconds_between_rounds': GAP_SECONDS,
            'node_workers': WORKERS, 'requests_per_node_in_parallel': 1,
            'targets': {k: SITES[k] for k in TARGETS}, 'tls_hostname': TLS_HOST,
            'failed_round_stops_extra_requests': True, 'every_node_retried_next_round': True,
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


def page_probe_passed(label, item):
    return ((item.get('status') == 'passed' or (item.get('status') == 'verification_required'
            and confirmed_cloudflare_challenge(label, item)))
        and finite(item.get('elapsed_ms')) and 0 <= item['elapsed_ms'] <= 5000)


def round_passed(sample):
    sites = sample.get('sites') or {}
    return (set(sites) == set(TARGETS) and all(
        page_probe_passed(label, sites[label]) for label in TARGETS)
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
    if isinstance(result, dict) and result.get('version') in (2, 3):
        import continuous_stability
        return continuous_stability.passed(result)
    return isinstance(result, dict) and result.get('status') == 'passed' and evidence_passed(result)


def core_metrics(result):
    """Derive latency from actual samples rather than trusting cached summaries."""
    if result.get('version') in (2, 3):
        import continuous_stability
        return continuous_stability.core_metrics(result)
    values = {label: [x['sites'][label]['elapsed_ms'] for x in result['attempts']
        if x['sites'][label].get('status') == 'passed'] for label in ('Google', 'YouTube')}
    values = {label: items for label, items in values.items() if items}
    return {label: {'median_ms': statistics.median(items), 'tail_ms': max(items),
                    'jitter_ms': max(items) - min(items)} for label, items in values.items()}


def quality_passed(result, median_limit, tail_limit, jitter_limit):
    if isinstance(result, dict) and result.get('version') in (2, 3):
        return passed(result)
    return passed(result) and all(item['median_ms'] <= median_limit
        and item['tail_ms'] <= tail_limit and item['jitter_ms'] <= jitter_limit
        for item in core_metrics(result).values())


def summarize(attempts):
    result = {'version': VERSION, 'attempts': attempts, 'round_count': len(attempts),
              'passed_count': sum(round_passed(x) for x in attempts),
              'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds')}
    result['status'] = ('incomplete' if len(attempts) != ROUNDS else
                        'passed' if evidence_passed(result) else 'failed')
    result['failures'] = [{'round': sample['round'], 'target': label,
        'status': sample['sites'][label].get('status'),
        'reason': sample['sites'][label].get('reason')}
        for sample in attempts for label in TARGETS
        if sample['sites'][label].get('status') != 'skipped' and (not page_probe_passed(label, sample['sites'][label]))]
    result['failures'] += [{'round': sample['round'], 'target': TLS_HOST,
        'status': sample['android_tls'].get('status'),
        'reason': sample['android_tls'].get('error_type', 'unverified_or_late_TLS')}
        for sample in attempts if sample['android_tls'].get('status') != 'skipped' and not tls_passed(sample['android_tls'])]
    result['skipped_count'] = sum(x['sites'][k].get('status') == 'skipped' for x in attempts for k in TARGETS)
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
    sites, stopped = {}, False
    for label in TARGETS:
        sites[label] = ({'status': 'skipped', 'reason': '本轮前置请求失败，下一轮重新检查'} if stopped
                        else check_site(port, label, SITES[label]))
        item = sites[label]
        stopped = stopped or not page_probe_passed(label, item)
    tls = ({'status': 'skipped', 'hostname': TLS_HOST, 'reason': '本轮前置请求失败，下一轮重新检查'}
           if stopped else app_tls.probe(port, TLS_HOST))
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


def core_health(core, root):
    """Record counts only; controller payloads and core logs stay private."""
    result = {'process_alive': core.process.poll() is None}
    try:
        result['open_connections'] = len(core.get('/connections').get('connections') or [])
        result['api_available'] = True
    except Exception as error:
        result.update(api_available=False, api_error_type=type(error).__name__)
    try:
        fd_path = Path('/proc') / str(core.process.pid) / 'fd'
        if fd_path.exists():
            result['open_file_descriptors'] = len(list(fd_path.iterdir()))
        log_path = Path(root) / 'core.log'
        result['file_limit_errors'] = log_path.read_text(errors='replace').lower().count('too many open files') if log_path.exists() else 0
    except OSError as error:
        result['resource_measurement_error'] = type(error).__name__
    return result


def core_healthy(result):
    return result.get('process_alive') is True and result.get('api_available') is True and result.get('file_limit_errors', 0) == 0


def recheck_summary(records, diagnostic=None, previous=None, quality=None):
    """Do not mix older observations into this recheck's counts."""
    previous = previous or {}
    if diagnostic and diagnostic.get('node_count'):
        ids = {x['id'] for x in diagnostic['nodes']}
        info = {'updated_at': diagnostic['updated_at'], 'node_count': len(ids),
                'controls_valid': diagnostic['controls_valid'], 'scope': diagnostic.get('scope', 'eligible_pool_after_downloads')}
    elif previous:
        info = dict(previous)
        ids = set(previous.get('node_ids') or [])
        if not ids:
            # Older schema-17 rechecks omitted IDs. Recover only an exact-size
            # measurement cohort, using the per-node timestamp (not publication).
            updated = s.datetime.fromisoformat(previous['updated_at'])
            ids = {r['id'] for r in records if (r.get('stability') or {}).get('updated_at')
                and 0 <= (updated - s.datetime.fromisoformat(r['stability']['updated_at'])).total_seconds() <= 3}
            if len(ids) != previous['node_count']:
                return previous
    else:
        return None
    cohort = [r for r in records if r['id'] in ids]
    if len(cohort) != len(ids):
        raise ValueError('稳定性复测摘要缺少对应节点记录')
    info.update(node_ids=sorted(ids),
        passed_count=sum(passed(r.get('stability')) for r in cohort),
        failed_count=sum((r.get('stability') or {}).get('status') == 'failed' for r in cohort),
        quality_eligible_count=sum(passed(r.get('stability')) and quality(r) for r in cohort))
    return info


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
    health = []
    def snapshot(complete):
        results = {id: summarize(attempts) for id, attempts in samples.items()}
        control_ok = all(core_healthy(x) for x in health) and all(x['sites']['Google204'].get('status') == 'passed'
                         and tls_passed(x.get('android_tls')) for x in controls)
        diagnostic = {'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds'),
                      'settings': settings(), 'node_count': len(records), 'complete': complete,
                      'controls_valid': control_ok if complete else None,
                      'controls': controls, 'core_health': health, 'nodes': [{'id': r['id'], 'previous_name': r.get('name'),
                          'stability': results[r['id']]} for r in records]}
        checkpoint = root / 'stability-results.tmp'
        checkpoint.write_text(json.dumps(diagnostic, ensure_ascii=False, indent=2) + '\n')
        checkpoint.replace(root / 'stability-results.json')
        return diagnostic, results
    with s.Core(binary, root, [mapping[r['id']] for r in records], listeners) as core:
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
                health.append({'round': number, **core_health(core, root)})
                count = sum(all(round_passed(x) for x in samples[r['id']]) for r in records)
                print(f'间隔稳定性 {number}/{ROUNDS}：{len(records)}节点，目前全轮通过{count}；节点并发{WORKERS}', flush=True)
                snapshot(False)
    # A runner-control outage aborts publication; partial records never qualify.
    diagnostic, results = snapshot(True)
    if not diagnostic['controls_valid']:
        raise RuntimeError('测速内核、云端直连204或Android TLS对照异常，稳定性记录已保存；不据此淘汰或发布')
    for record in records:
        record['stability'] = results[record['id']]
    return diagnostic
