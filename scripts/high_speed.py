"""Two complete downloads from independent targets qualify the high-speed pool."""
import math

VERSION = 1
BYTES = 100_000_000
BUDGET = 20
WORKERS = 2
URLS = (
    'https://speed.cloudflare.com/__down?bytes=100000000',
    'http://lax.download.datapacket.com/100mb.bin',
)


def request_headers(url):
    # The official download endpoint requires its speed-site Referer for 100 MB.
    return {'Referer': 'https://speed.cloudflare.com/'} if url == URLS[0] else {}


def settings():
    return {'version': VERSION, 'urls': list(URLS), 'bytes': BYTES,
            'budget_seconds': BUDGET, 'rounds': len(URLS), 'sequential_per_node': True,
            'workers_per_shard': WORKERS, 'selection_limit': None,
            'read_timeout_seconds': 1, 'includes_handshake': True,
            'required_request_headers': {url: request_headers(url) for url in URLS},
            'speed_aggregation': 'minimum_of_completed_rounds'}


def sample_passed(sample, url):
    elapsed, speed = sample.get('elapsed_ms'), sample.get('speed_mib_s')
    return (sample.get('status') == 'passed' and sample.get('url') == url
            and sample.get('requested_bytes') == sample.get('received_bytes') == BYTES
            and sample.get('budget_seconds') == BUDGET
            and isinstance(elapsed, (int, float)) and math.isfinite(elapsed)
            and 0 < elapsed <= BUDGET * 1000
            and isinstance(speed, (int, float)) and math.isfinite(speed) and speed > 0
            and abs(speed - BYTES / (elapsed / 1000) / 1048576) <= .01)


def summarize(attempts):
    passed_count = sum(sample_passed(sample, url) for sample, url in zip(attempts, URLS))
    complete = len(attempts) == len(URLS) and passed_count == len(URLS)
    return {'version': VERSION, 'status': 'passed' if complete else 'failed',
            'round_count': len(attempts), 'passed_count': passed_count,
            'attempts': attempts, 'budget_seconds_per_round': BUDGET,
            'speed_mib_s': min(a['speed_mib_s'] for a in attempts) if complete else None,
            'reason': '两个100 MB文件均在各自20秒内完整下载' if complete else '两轮100 MB下载未全部通过'}


def passed(result):
    attempts = result.get('attempts') or []
    if (result.get('version') != VERSION or result.get('status') != 'passed'
            or result.get('round_count') != len(URLS) or len(attempts) != len(URLS)
            or result.get('passed_count') != len(URLS)
            or result.get('budget_seconds_per_round') != BUDGET):
        return False
    if not all(sample_passed(sample, url) for sample, url in zip(attempts, URLS)):
        return False
    return result.get('speed_mib_s') == min(a['speed_mib_s'] for a in attempts)


def status_counts(records, index):
    counts = dict.fromkeys(('passed', 'failed', 'skipped'), 0)
    for record in records:
        attempts = (record.get('high_speed_download') or {}).get('attempts') or []
        sample = attempts[index] if len(attempts) > index else {}
        status = 'passed' if sample_passed(sample, URLS[index]) else 'failed' if sample else 'skipped'
        counts[status] += 1
    return counts


def result_counts(records):
    counts = dict.fromkeys(('passed', 'failed', 'skipped', 'unverified'), 0)
    for record in records:
        result = record.get('high_speed_download') or {}
        status = result.get('status')
        if status == 'passed' and not passed(result):
            status = 'unverified'
        counts[status if status in counts else 'unverified'] += 1
    return counts
