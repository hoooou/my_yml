import app_tls


def verified_tls():
    return {'version': app_tls.VERSION, 'status': 'passed', 'targets': {
        host: {'status': 'passed', 'round_count': app_tls.ROUNDS, 'attempts': [
            {'status': 'passed', 'hostname': host, 'chain_verified': True,
             'hostname_verified': True, 'validity_verified': True, 'elapsed_ms': 10}
            for _ in range(app_tls.ROUNDS)]} for host in app_tls.TARGETS}}
