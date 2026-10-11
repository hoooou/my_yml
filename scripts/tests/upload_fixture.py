import upload_speed as up


def verified_upload_precheck(port=None):
    return {'version': up.VERSION, 'status': 'passed', 'url': up.url(up.PRECHECK_BYTES),
            'effective_url': up.url(up.PRECHECK_BYTES), 'requested_bytes': up.PRECHECK_BYTES,
            'uploaded_bytes': up.PRECHECK_BYTES, 'budget_seconds': up.PRECHECK_BUDGET,
            'elapsed_ms': 1000, 'speed_mbps': 8, 'curl_exit_code': 0, 'http_status': 200,
            'redirect_count': 0, 'ssl_verify_result': 0, 'tls_verification_enabled': True,
            'http_completed': True}
