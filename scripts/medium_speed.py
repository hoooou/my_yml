"""Complete 5 MB sampling qualifies the medium-download group."""
import math

BYTES = 5_000_000
BUDGET = 10
WORKERS = 4
URL = f'https://speed.cloudflare.com/__down?bytes={BYTES}'
GROUP = '🚄 中速下载'


def settings(total_deadline=False):
    return {'url': URL, 'bytes': BYTES, 'budget_seconds': BUDGET, 'rounds': 1,
            'workers_per_shard': WORKERS, 'read_timeout_seconds': None if total_deadline else 1,
            'total_deadline': total_deadline,
            'includes_handshake': True, 'selection_limit': None,
            'requires_1mb_pass': True, 'failure_blocks_high_speed_test': True}


def passed(sample):
    elapsed, speed = sample.get('elapsed_ms'), sample.get('speed_mib_s')
    return (sample.get('status') == 'passed' and sample.get('url') == URL
            and sample.get('requested_bytes') == sample.get('received_bytes') == BYTES
            and sample.get('budget_seconds') == BUDGET and sample.get('http_status') == 200
            and sample.get('response_length') == str(BYTES)
            and (sample.get('response_type') or '').split(';')[0] == 'application/octet-stream'
            and sample.get('response_encoding') == 'identity'
            and isinstance(elapsed, (int, float)) and math.isfinite(elapsed)
            and 0 < elapsed <= BUDGET * 1000
            and isinstance(speed, (int, float)) and math.isfinite(speed) and speed > 0
            and abs(speed - BYTES / (elapsed / 1000) / 1048576) <= .01)


def counts(records):
    results = dict.fromkeys(('passed', 'failed', 'skipped', 'unverified'), 0)
    for record in records:
        sample = record.get('medium_speed_download') or {}
        status = 'passed' if passed(sample) else ('unverified' if sample.get('status') == 'passed'
                                               else sample.get('status', 'skipped'))
        results[status if status in results else 'unverified'] += 1
    return results
