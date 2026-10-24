"""Versioned stability-first decisions; legacy evidence keeps its old rules."""
VERSION = 2
TRANSIENT = {'ReadTimeout', 'ConnectTimeout', 'Timeout', 'ConnectionError',
             'timeout', 'connection_or_protocol_failed'}


def modern(record):
    return record.get('selection_policy_version') == VERSION


def transient(sample):
    return (sample.get('status') == 'failed' and sample.get('error_type') in TRANSIENT
            and not sample.get('tls_error_kind') and not sample.get('http_status'))


def tls_errors(item):
    if not isinstance(item, dict):
        return False
    if (item.get('tls_error_kind') or item.get('error_type') in
            ('SSLError', 'certificate_verification_failed', 'tls_handshake_failed')):
        return True
    return any(tls_errors(value) for value in item.values() if isinstance(value, dict)) or any(
        tls_errors(value) for values in item.values() if isinstance(values, list)
        for value in values if isinstance(value, dict))


def accepted(label, item, exception, trace=False):
    """One recovered transport failure is allowed, never HTTP/TLS restrictions."""
    attempts = item.get('attempts') or []
    if item.get('round_count') not in ((1, 2) if trace else (3,)) or len(attempts) != item['round_count']:
        return False
    good = [a.get('status') == 'passed' or (not trace and exception(label, a)) for a in attempts]
    if all(good):
        return True
    failures = [a for a, ok in zip(attempts, good) if not ok]
    return (len(failures) == 1 and transient(failures[0])
            and sum(good) >= (1 if trace else 2)
            and (not trace or len(attempts) == 2 and good[-1]))


def upload_observed(record):
    """Speed is a grade; missing measurement or TLS errors cannot pass."""
    upload = record.get('upload') or {}
    attempts = upload.get('attempts') or []
    import upload_speed as up
    write_works = (up.sample_passed(record.get('upload_precheck') or {}, up.PRECHECK_BYTES, up.PRECHECK_BUDGET)
                   or any(up.sample_passed(a) for a in attempts)
                   or up.sample_passed(upload.get('basic_write') or {}, 64_000, up.PRECHECK_BUDGET))
    return (upload.get('selection_policy_version') == VERSION and len(attempts) == 2
            and write_works
            and upload.get('idle_seconds', 0) >= 20
            and all(a.get('version') == up.VERSION and a.get('status') in ('passed', 'failed') and a.get('requested_bytes') == 5_000_000
                    and a.get('budget_seconds') == 10 and a.get('tls_verification_enabled') is True
                    and bool(a.get('loaded_204'))
                    and (a.get('status') != 'passed' or up.sample_passed(a)) for a in attempts)
            and not tls_errors(upload) and not tls_errors(record.get('upload_precheck')))


def settings():
    return {'version': VERSION, 'name': 'stability_first', 'minimum_success_rate': .9,
            'upload_rate_is_hard_gate': False, 'website_minimum_accepted_of_three': 2,
            'website_allowed_failure': 'one_transport_failure_only', 'trace_transient_retry': 1,
            'strict_tls_errors_reject': True, 'history_days': 7,
            'ordinary_requires_complete_1mb': True, 'large_downloads_only_grade': True}
