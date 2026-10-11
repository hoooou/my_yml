"""Archive each completed full measurement, including zero-qualified runs."""
from collections import Counter
import json
import app_tls
import high_speed
import medium_speed
import stability
import upload_speed


def write_attempt(root, records, config, required_sites, sources, input_count, now, required_traces=(), required_gate=None, stability_policy=None):
    coverage = {}
    labels = {label for record in records for label in (record.get('websites') or {})}
    for label in sorted(labels):
        items = [(r.get('websites') or {}).get(label) for r in records]
        measured = [item for item in items if item]
        attempts = [attempt for item in measured for attempt in item.get('attempts', [])]
        coverage[label] = {'node_status_counts': dict(Counter(item['status'] for item in measured)),
            'unmeasured_nodes': len(items) - len(measured),
            'attempt_http_status_counts': dict(Counter(str(a.get('http_status', 'no_response')) for a in attempts)),
            'attempt_reason_counts': dict(Counter(a.get('reason', 'unknown') for a in attempts))}
    selected = len(config['proxies'])
    report = {'updated_at': now, 'scope': 'all_subscriptions', 'input_unique_count': input_count,
        'parseable_count': len(records), 'selected_node_count': selected,
        'selection_outcome': 'candidate_ready' if selected else 'no_eligible_nodes_previous_subscription_retained',
        'required_websites': list(required_sites), 'required_rounds': 3,
        'confirmed_cloudflare_challenge': 'accepted_access_verification_required',
        'challenge_in_page_speed_ranking': False,
        'required_traces': list(required_traces), 'required_trace_rounds': 1,
        'app_tls_policy': {'version': app_tls.VERSION, 'targets': list(app_tls.TARGETS),
            'rounds_per_target': app_tls.ROUNDS, 'budget_seconds_per_handshake': app_tls.BUDGET_SECONDS,
            'android_certificate_pinning_emulated': False},
        'app_tls_counts': dict(Counter((r.get('app_tls') or {}).get('status', 'missing') for r in records)),
        'stability_policy': stability_policy or stability.settings(records),
        'upload_policy': upload_speed.settings(),
        'upload_precheck_policy': upload_speed.precheck_settings(),
        'early_upload_precheck_enabled': all('upload_precheck' in r for r in records),
        'upload_precheck_counts': dict(Counter((r.get('upload_precheck') or {}).get('status', 'missing') for r in records)),
        'upload_counts': dict(Counter((r.get('upload') or {}).get('status', 'not_candidate') for r in records)),
        'post_upload_tls_counts': dict(Counter((r.get('post_upload_tls') or {}).get('status', 'not_candidate') for r in records)),
        'stability_counts': dict(Counter((r.get('stability') or {}).get('status', 'not_candidate') for r in records)),
        'stability_failure_targets': dict(Counter(f['target'] for r in records
            for f in (r.get('stability') or {}).get('failures', []))),
        'precheck_counts': dict(Counter((r.get('precheck') or {}).get('status', 'missing') for r in records)),
        'entry_counts': dict(Counter(r['entry']['status'] for r in records)),
        'download_counts': dict(Counter((r.get('download') or {}).get('status', 'missing') for r in records)),
        'medium_speed_download_counts': medium_speed.counts(records),
        'medium_speed_download_settings': medium_speed.settings(),
        'high_speed_download_counts': high_speed.result_counts(records),
        'high_speed_download_settings': high_speed.settings(),
        'high_speed_target_counts': {url: high_speed.status_counts(records, i) for i, url in enumerate(high_speed.URLS)},
        'website_counts': coverage, 'sources': sources, 'nodes': records}
    from detection_report import write_report
    names = {n['name'] for n in config['proxies']}
    report.update(publication_mode='full', published_node_count=selected,
                  published_node_ids=[r['id'] for r in records if r.get('name') in names])
    (root / 'full-test-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    write_report(report, config, root / 'full-test-report.md', candidate=True, website_gate=required_gate)
    print(f'本次全量检测记录已保存：可解析 {len(records)}；候选入选 {selected}', flush=True)
