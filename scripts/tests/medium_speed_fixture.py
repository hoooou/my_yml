"""Complete 5 MB evidence without network access in regression tests."""
import medium_speed as m


def verified_medium(speed=10):
    return {'status': 'passed', 'url': m.URL, 'requested_bytes': m.BYTES,
            'received_bytes': m.BYTES, 'budget_seconds': m.BUDGET,
            'http_status': 200, 'response_length': str(m.BYTES),
            'response_type': 'application/octet-stream', 'response_encoding': 'identity',
            'request_headers': {'Referer': 'https://speed.cloudflare.com/'},
            'elapsed_ms': round(m.BYTES / speed / 1048576 * 1000, 1), 'speed_mib_s': speed}
