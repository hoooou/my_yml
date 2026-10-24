"""Protocol candidates only; domestic TCP does not qualify a Worker upstream."""
import copy


def collect(nodes):
    candidates = []
    for node in nodes:
        if node.get('type') not in ('http', 'socks5'):
            continue
        candidates.append({'id': node['name'], 'node': copy.deepcopy(node),
            'upstream_type': 'https' if node.get('tls') else node['type'],
            'status': 'untested_worker_chain', 'native_proxyip': False,
            'custom_sni_requires_validation': bool(node.get('sni')),
            'upstream_certificate_validation_required': bool(node.get('tls'))})
    return {'version': 1, 'scope': 'public_sources_before_domestic_TCP', 'candidates': candidates,
            'count': len(candidates), 'worker_chain_tested': False,
            'credentials_in_artifact_only': True, 'live_subscription_inclusion': False}


def summary(pool):
    return {k: v for k, v in pool.items() if k != 'candidates'}
