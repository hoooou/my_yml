"""Seven days of compact evidence, never node credentials or reused passes."""
from datetime import datetime, timedelta, timezone
import statistics

TZ = timezone(timedelta(hours=8))
VERSION = 1


def update(records, previous, now, run):
    import continuous_stability as cs
    cutoff = datetime.fromisoformat(now) - timedelta(days=7)
    old = (previous or {}).get('nodes', {}) if (previous or {}).get('version') == VERSION else {}
    nodes = {}
    current = {r['id']: r for r in records}
    for id in set(old) | set(current):
        samples = []
        for x in old.get(id, []):
            try:
                if datetime.fromisoformat(x['time']) >= cutoff and x.get('run') != str(run):
                    samples.append(x)
            except (KeyError, ValueError, TypeError):
                continue
        row = current.get(id)
        stable = (row or {}).get('stability') or {}
        if stable.get('version') == cs.VERSION and cs.valid_evidence(stable):
            metrics = cs.metrics(stable)
            observed_at = stable['attempts'][-1].get('started_at') or now
            p95 = max((v['p95_ms'] for v in cs.core_metrics(stable).values()), default=None)
            samples.append({'run': str(run), 'time': observed_at, 'hour': datetime.fromisoformat(observed_at).astimezone(TZ).hour,
                'rounds': metrics['round_count'], 'good': metrics['passed_count'],
                'streak': metrics['maximum_consecutive_failures'], 'p95': p95,
                'window': stable.get('window_seconds', 0), 'tls_error': any(cs.certificate_error(a) for a in stable['attempts'])})
        elif row and samples:
            # A formerly good node failing this round remains visible in history.
            samples.append({'run': str(run), 'time': now, 'hour': datetime.fromisoformat(now).astimezone(TZ).hour,
                            'unobserved': True, 'entry': row.get('entry', {}).get('status', 'unknown')})
        if samples:
            nodes[id] = samples[-32:]
        if row:
            row['quality_history'] = summarize(samples)
    return {'version': VERSION, 'days': 7, 'updated_at': now, 'nodes': nodes}


def summarize(samples):
    measured = [x for x in samples if x.get('rounds', 0) > 0]
    total = sum(x['rounds'] for x in measured)
    good = sum(x['good'] for x in measured)
    peak = [x['p95'] for x in measured if 20 <= x['hour'] < 24 and x.get('p95') is not None]
    off = [x['p95'] for x in measured if 8 <= x['hour'] < 18 and x.get('p95') is not None]
    days = len({x['time'][:10] for x in measured})
    return {'measured_runs': len(measured), 'days': days, 'rounds': total,
            'success_rate': good / total if total else None,
            'worst_run_success_rate': min((x['good'] / x['rounds'] for x in measured), default=None),
            'maximum_consecutive_failures': max((x['streak'] for x in measured), default=0),
            'unobserved_runs': sum(x.get('unobserved', False) for x in samples),
            'failed_entry_runs': sum(x.get('entry') == 'failed' for x in samples),
            'peak_runs': len(peak), 'off_peak_runs': len(off),
            'peak_p95_ratio': statistics.median(peak) / statistics.median(off) if peak and off and statistics.median(off) > 0 else None,
            'confidence': 'multi_period' if days >= 2 and peak and off and total >= 100 else 'provisional'}


def rank(record):
    x = record.get('quality_history') or {}
    rate = x.get('success_rate')
    # Unknown history never masquerades as historical perfection.
    return (-(rate if rate is not None else 0), x.get('failed_entry_runs', 0),
            x.get('maximum_consecutive_failures', 0), x.get('confidence') != 'multi_period')


def summary(records):
    import continuous_stability as cs
    histories = [r.get('quality_history') or {} for r in records if r.get('stability')]
    observed = [r['stability'] for r in records if (r.get('stability') or {}).get('version') == cs.VERSION]
    bands = {'100%': 0, '99%-100%': 0, '95%-99%': 0, '90%-95%': 0, '<90%': 0}
    for item in observed:
        rate = cs.metrics(item)['success_rate']
        bands['100%' if rate == 1 else '99%-100%' if rate >= .99 else '95%-99%' if rate >= .95 else '90%-95%' if rate >= .9 else '<90%'] += 1
    return {'observed_nodes': len(histories),
            'multi_period_nodes': sum(x.get('confidence') == 'multi_period' for x in histories),
            'provisional_nodes': sum(x.get('confidence') != 'multi_period' for x in histories),
            'peak_observed_nodes': sum(x.get('peak_runs', 0) > 0 for x in histories),
            'success_rate_bands': bands,
            'passed_observations': sum(cs.passed(x) for x in observed),
            'unrecovered_nodes': sum(cs.metrics(x)['unrecovered_at_end'] for x in observed)}


def compare(current, previous):
    if not previous:
        return {'available': False, 'reason': '没有同口径的上一轮稳定性摘要'}
    keys = ('observed_nodes', 'passed_observations', 'unrecovered_nodes', 'multi_period_nodes')
    return {'available': True, 'differences': {key: current.get(key, 0) - previous.get(key, 0) for key in keys}}
