"""Complete independent-target download evidence for selection tests."""
import high_speed


def verified_high(speed=10):
    elapsed = round(high_speed.BYTES / speed / 1048576 * 1000, 1)
    return high_speed.summarize([{'status': 'passed', 'requested_bytes': high_speed.BYTES,
        'received_bytes': high_speed.BYTES, 'url': url, 'budget_seconds': high_speed.BUDGET,
        'elapsed_ms': elapsed, 'speed_mib_s': speed} for url in high_speed.URLS])
