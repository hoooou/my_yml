import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a
import app_tls
import continuous_stability as cs
import quality_policy as qp
import quality_history as history
import transfer_probe
import application_quality
import edge_candidates
from test_stability import sample
from tls_fixture import verified_tls
from upload_fixture import verified_upload_precheck
from test_upload_speed import sample as upload_sample


def evidence(failures=0, count=31):
    attempts = [sample(i + 1, i * 21) for i in range(count)]
    for item in attempts:
        item['connection_reuse'] = {'status': 'passed', 'elapsed_ms': 100}
    for item in attempts[:failures]:
        item['sites']['Google204'].update(status='failed', error_type='ReadTimeout')
    return cs.summarize(attempts, cutoff=0)


def row(id='n-a', failures=0):
    result = {'id': id, 'selection_policy_version': qp.VERSION, 'entry': {'status': 'passed'},
              'precheck': {'status': 'passed', 'round_count': 3, 'passed_count': 3},
              'app_tls': verified_tls(), 'post_upload_tls': verified_tls(),
              'stability': evidence(failures), 'download': {'status': 'passed', 'speed_mib_s': 1},
              'exit': {'country_code': 'US', 'exit_ip': '8.8.8.8'},
              'upload_precheck': {'status': 'failed', 'error_type': 'timeout'},
              'upload': {'selection_policy_version': qp.VERSION, 'status': 'failed', 'idle_seconds': 20,
                  'basic_write': upload_sample(64_000, 6),
                  'attempts': [dict(upload_sample(), status='failed', error_type='timeout') for _ in range(2)]}}
    pages = {k: {'status': 'passed', 'elapsed_ms': 100} for k in a.DAILY_POST_SITES}
    result['websites'] = a.summarize_rounds([pages]*3, a.OVERSEAS_SITES)
    result['websites'].update(a.summarize_rounds([pages], [k for k in a.DAILY_POST_SITES if k not in a.OVERSEAS_SITES]))
    return result


class PolicyTests(unittest.TestCase):
    def test_required_sites_recover_one_transport_failure_never_http_or_tls(self):
        for error, expected in (({'error_type': 'ReadTimeout'}, True),
                ({'error_type': 'ConnectionError'}, True), ({'http_status': 403}, False),
                ({'tls_error_kind': 'tls_handshake_or_transport_failed'}, False),
                ({'error_type': 'SSLError'}, False)):
            r = row()
            attempts = r['websites']['YouTube']['attempts']
            attempts[0] = {'status': 'failed', **error}
            r['websites']['YouTube'] = a.summarize_rounds([{'YouTube': p} for p in attempts], ('YouTube',))['YouTube']
            self.assertEqual(a.required_websites_passed(r), expected, error)
            self.assertEqual(a.web_quality_eligible(r), expected, error)
        r = row()
        r['websites']['YouTube']['attempts'][0]['status'] = 'failed'
        r['websites']['YouTube']['attempts'][1]['status'] = 'failed'
        self.assertFalse(a.required_websites_passed(r))

    def test_trace_only_recovered_transport_retry_passes(self):
        r = row()
        for failure, expected in (({'error_type': 'ReadTimeout'}, True), ({'http_status': 403}, False)):
            attempts = [{'status': 'failed', **failure}, {'status': 'passed'}]
            r['websites']['ClaudeTrace'] = a.summarize_rounds([{'ClaudeTrace': p} for p in attempts], ('ClaudeTrace',))['ClaudeTrace']
            self.assertEqual(a.required_websites_passed(r), expected)

    def test_upload_rate_failure_does_not_remove_stable_node_but_tls_or_missing_measurement_does(self):
        r = row()
        mapping = {r['id']: {'name': r['id'], 'type': 'http', 'server': '8.8.8.8', 'port': 80}}
        self.assertTrue(qp.upload_observed(r))
        self.assertEqual(len(a.render_comparison({}, [r], mapping, True, True)['proxies']), 1)
        for bad in ('certificate_verification_failed', 'tls_handshake_failed'):
            r['upload']['attempts'][0]['error_type'] = bad
            self.assertFalse(a.render_comparison({}, [r], mapping, True, True)['proxies'])
        r = row(); r['upload']['attempts'].pop()
        self.assertFalse(qp.upload_observed(r))

    def test_comprehensive_url_test_contains_stablest_tier_not_fast_unstable_node(self):
        rows = [row('n-steady'), row('n-variable', 3)]
        mapping = {r['id']: {'name': r['id'], 'type': 'http', 'server': '8.8.8.8', 'port': 80} for r in rows}
        config = a.render_comparison({}, rows, mapping, True, True)
        self.assertEqual(len(config['proxies']), 2)
        group = next(g for g in config['proxy-groups'] if g['name'] == '⭐ 综合优选')
        self.assertEqual(group['proxies'], [rows[0]['name']])


class PipelineTests(unittest.TestCase):
    def test_modern_publication_merges_slow_upload_and_independent_raw_observations(self):
        from medium_speed_fixture import verified_medium
        from high_speed_fixture import verified_high
        from test_upload_speed import evidence as upload_evidence
        node = {'name': 'n-a', 'type': 'http', 'server': '8.8.8.8', 'port': 80}
        pre = a.summarize_rounds([{'Google204': {'status': 'passed', 'elapsed_ms': 100}}]*3, ('Google204',))['Google204']
        controls = {}
        with patch.object(a.s, 'Core'), patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1234})), \
                patch.object(a.s, 'query_exit', return_value=None), patch.object(a.app_tls, 'check', return_value=verified_tls()), \
                patch.object(a.application_quality, 'check', return_value={'status': 'diagnostic_only'}):
            records, endpoints = a.probe_pipeline([node], 'unused', Path('.'),
                precheck=lambda p: pre, probe=lambda *_: {'status': 'passed'},
                upload_precheck=lambda p: verified_upload_precheck() if p is None else {'status': 'failed', 'error_type': 'timeout'},
                upload_controls=controls, policy_version=qp.VERSION,
                site_check=lambda p: {k: {'status': 'passed', 'elapsed_ms': 100} for k in a.DAILY_POST_SITES},
                download=lambda p: {'status': 'passed', 'received_bytes': a.DOWNLOAD_BYTES, 'elapsed_ms': 1000, 'speed_mib_s': 1},
                medium_download=lambda p: verified_medium(), large_download=lambda p: verified_high())
        bundle = {'id': 'batch', 'nodes': [node], 'selection_policy_version': qp.VERSION,
                  'early_upload_precheck': True, 'stability_policy': cs.settings()}
        part = {'bundle_id': 'batch', 'index': 0, 'count': 1, 'records': records,
                'endpoint_count': endpoints, 'upload_precheck_controls': controls}
        merged, _ = a.merge_shards(bundle, [part], 1)
        upload_row = copy.deepcopy(merged[0]); upload_row.update(upload=row()['upload'], post_upload_tls=verified_tls())
        upload_row['upload']['precheck'] = upload_row['upload_precheck']
        diagnostic = {'node_count': 1, 'controls_valid': True, 'nodes': [{'id': 'n-a',
            'upload': upload_row['upload'], 'post_upload_tls': upload_row['post_upload_tls']}],
            'controls': {'before': upload_evidence(), 'after': upload_evidence()},
            'core_health': {'process_alive': True, 'api_available': True}}
        a.merge_uplink(bundle, merged, {'bundle_id': 'batch', 'records': [upload_row], 'diagnostic': diagnostic}, {'n-a': node})
        checks = [{'sites': {'Google204': {'status': 'passed', 'elapsed_ms': 100}},
            'android_tls': sample(1)['android_tls'], 'started_offset_seconds': i*60,
            'finished_offset_seconds': i*60+1} for i in range(12)]
        observer = {'bundle_id': 'batch', 'index': 0, 'count': 1, 'diagnostic': {
            'settings': cs.settings(), 'updated_at': '2026-10-25T11:00:00+08:00', 'node_count': 1,
            'complete': True, 'controls_valid': True, 'controls': checks,
            'core_health': [{'process_alive': True, 'api_available': True}],
            'nodes': [{'id': 'n-a', 'stability': evidence()}]}}
        cs.merge(bundle, [observer], merged, 1, a.shard_nodes)
        config = a.render_comparison({}, merged, {'n-a': node}, True, True)
        self.assertEqual(len(config['proxies']), 1)
        self.assertEqual(merged[0]['upload_precheck']['status'], 'failed')

    def test_tcp_preflight_does_not_upload_and_failed_upload_continues_through_merge(self):
        node = {'name': 'n-a', 'type': 'http', 'server': '8.8.8.8', 'port': 80}
        pre = a.summarize_rounds([{'Google204': {'status': 'passed', 'elapsed_ms': 100}}]*3, ('Google204',))['Google204']
        controls = {}
        with patch.object(a.s, 'Core'), patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1234})), \
                patch.object(a.s, 'query_exit', return_value=None), patch.object(a.app_tls, 'check', return_value=verified_tls()), \
                patch.object(a.application_quality, 'check', return_value={'status': 'diagnostic_only'}):
            upload = Mock(side_effect=lambda p: verified_upload_precheck() if p is None else {'status': 'failed', 'error_type': 'timeout'})
            pages = Mock(return_value={k: {'status': 'passed', 'elapsed_ms': 100} for k in a.DAILY_POST_SITES})
            first, count = a.probe_pipeline([node], 'unused', Path('.'), precheck=lambda p: pre,
                probe=lambda *_: {'status': 'passed'}, upload_precheck=upload, upload_controls=controls,
                site_check=pages, preflight_only=True, policy_version=qp.VERSION)
            upload.assert_not_called(); pages.assert_not_called()
            bundle = {'id': 'batch', 'nodes': [node], 'early_upload_precheck': True, 'selection_policy_version': qp.VERSION}
            part = {'bundle_id': 'batch', 'count': 1, 'index': 0, 'records': first, 'endpoint_count': count, 'upload_precheck_controls': controls}
            a.merge_shards(bundle, [part], 1, preflight_only=True)
            second, count = a.probe_pipeline([node], 'unused', Path('.'), initial_records=first,
                upload_precheck=upload, upload_controls=controls, site_check=pages,
                download=lambda p: {'status': 'failed'}, policy_version=qp.VERSION)
            self.assertEqual(pages.call_count, 3); self.assertEqual(upload.call_count, 3)
            self.assertEqual(second[0]['upload_precheck']['status'], 'failed')
            self.assertEqual(second[0]['download']['status'], 'failed')
            part.update(records=second, endpoint_count=count)
            a.merge_shards(bundle, [part], 1)


class StabilityTests(unittest.TestCase):
    def test_ten_minute_window_reuse_and_raw_failures_are_required(self):
        self.assertTrue(cs.passed(evidence()))
        self.assertFalse(cs.passed(evidence(count=3)))
        self.assertTrue(cs.passed(evidence(3)))
        self.assertFalse(cs.passed(evidence(4)))
        x = evidence(); x['attempts'][0]['connection_reuse']['error_type'] = 'certificate_verification_failed'
        self.assertFalse(cs.passed(x))
        x = evidence(); x['attempts'][0].pop('connection_reuse')
        self.assertFalse(cs.passed(x))

    def test_request_counts_recovery_and_small_sample_percentiles(self):
        x = evidence(2); metrics = cs.metrics(x)
        self.assertEqual(metrics['maximum_consecutive_failures'], 2)
        self.assertGreater(metrics['maximum_recovery_seconds'], 40)
        self.assertEqual(metrics['request_count'], 31 * 6)
        self.assertIsNone(metrics['targets']['Google']['p99_ms'])
        x['attempts'][-1]['connection_reuse']['status'] = 'failed'
        self.assertTrue(cs.metrics(x)['unrecovered_at_end'])


class HistoryTests(unittest.TestCase):
    def test_peak_hour_uses_actual_sample_time_not_publication_time(self):
        r = row()
        r['stability']['attempts'][-1]['started_at'] = '2026-10-25T22:30:00+08:00'
        h = history.update([r], None, '2026-10-26T01:00:00+08:00', '1')
        self.assertEqual(h['nodes'][r['id']][0]['hour'], 22)
        self.assertEqual(r['quality_history']['peak_runs'], 1)

    def test_history_is_bounded_deduplicated_and_never_reuses_passes(self):
        r = row()
        h = history.update([r], None, '2026-10-24T11:00:00+08:00', '1')
        self.assertEqual(r['quality_history']['confidence'], 'provisional')
        h = history.update([r], h, '2026-10-24T11:00:00+08:00', '1')
        self.assertEqual(len(h['nodes'][r['id']]), 1)
        h = history.update([r], h, '2026-10-25T23:00:00+08:00', '2')
        self.assertEqual(r['quality_history']['days'], 2)
        self.assertIsNotNone(r['quality_history']['peak_p95_ratio'])
        failed = {'id': r['id'], 'entry': {'status': 'failed'}}
        h = history.update([failed], h, '2026-10-26T11:00:00+08:00', '3')
        self.assertEqual(failed['quality_history']['failed_entry_runs'], 1)
        h = history.update([], h, '2026-11-05T11:00:00+08:00', '4')
        self.assertEqual(h['nodes'], {})


class AppAndTransferTests(unittest.TestCase):
    def test_large_upload_failure_falls_back_to_small_verified_write(self):
        import upload_speed as up
        failed = dict(upload_sample(), status='failed', error_type='timeout')
        with patch.object(up, 'loaded_sample', return_value=failed), \
                patch.object(up, 'sample', return_value=upload_sample(64_000, 6)) as fetch, \
                patch.object(up.time, 'sleep'), patch.object(up.time, 'monotonic', side_effect=[0, 20]):
            measured = up.check(1234, precheck={'status': 'failed'}, stability_first=True)
        self.assertEqual(fetch.call_args.args[1:3], (64_000, 6))
        r = row(); r['upload'] = measured
        self.assertTrue(qp.upload_observed(r)); self.assertEqual(measured['status'], 'failed')

    def test_modern_report_is_aggregate_and_does_not_call_it_authenticated_chat(self):
        import detection_report as d
        records = [row('n-' + str(i)) for i in range(15)]
        mapping = {r['id']: {'name': r['id'], 'type': 'http', 'server': '8.8.8.8', 'port': 80} for r in records}
        config = a.render_comparison({}, records, mapping, True, True)
        report = {'nodes': records, 'selection_policy': qp.settings(), 'stability_policy': cs.settings(),
                  'publication_mode': 'full', 'published_node_ids': [r['id'] for r in records]}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'report.md'; d.write_report(report, config, path)
            text = path.read_text()
        self.assertIn('10', text)
        self.assertIn('稳定性分布', text)
        self.assertLess(text.count('| 美国'), 15)
        self.assertNotIn('TCP与3MB上传通过即启动', text)

    def test_resource_discovery_never_fetches_untrusted_hosts_or_credentials(self):
        body = '<script src="/s/desktop/a.js"></script><img src="https://i.ytimg.com/a.jpg"><img src="https://evil.invalid/x.jpg"><script src="https://user:pass@www.youtube.com/a.js"></script>'
        self.assertEqual(application_quality.resources(body), ['https://www.youtube.com/s/desktop/a.js', 'https://i.ytimg.com/a.jpg'])
        self.assertEqual(application_quality.resources('<script src="https://[bad/a.js"><script src="https://www.youtube.com:bad/a.js">'), [])

    def test_tls_transient_retry_requires_two_verified_handshakes(self):
        good = next(iter(verified_tls()['targets'].values()))['attempts'][0]
        def measure(port, hostname):
            calls[hostname] = calls.get(hostname, 0) + 1
            return dict(good, hostname=hostname) if calls[hostname] != 1 else {'hostname': hostname, 'status': 'failed', 'error_type': 'timeout'}
        calls = {}
        with patch.object(app_tls, 'probe', side_effect=measure):
            result = app_tls.check(1234, retry_transient=True)
        self.assertTrue(app_tls.passed(result)); self.assertEqual(set(calls.values()), {3})
        result['targets']['chatgpt.com']['attempts'][0]['error_type'] = 'certificate_verification_failed'
        self.assertFalse(app_tls.passed(result))

    def test_download_total_deadline_keeps_exact_bytes_and_strict_tls(self):
        def run(command, **kwargs):
            self.assertNotIn('--insecure', command); self.assertNotIn('--location', command)
            self.assertEqual(command[command.index('--max-time')+1], '6')
            Path(command[command.index('--output')+1]).write_bytes(b'x'*100)
            Path(command[command.index('--dump-header')+1]).write_text('HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: application/octet-stream\r\n\r\n')
            return subprocess.CompletedProcess(command, 0, json.dumps({'time_total': 1, 'http_code': 200,
                'url_effective': 'https://speed.cloudflare.com/__down?bytes=100', 'ssl_verify_result': 0, 'time_starttransfer': .2}))
        with patch.object(transfer_probe.subprocess, 'run', side_effect=run):
            result = transfer_probe.download(1234, 100, 6)
        self.assertEqual(result['status'], 'passed'); self.assertEqual(result['received_bytes'], 100)

    def test_edge_candidates_are_independent_of_domestic_gate_and_not_native_proxyips(self):
        nodes = [{'name': 'n-a', 'type': 'http', 'tls': True}, {'name': 'n-b', 'type': 'socks5'},
                 {'name': 'n-c', 'type': 'vless'}, {'name': 'n-d', 'type': 'socks5', 'tls': True}]
        pool = edge_candidates.collect(nodes)
        self.assertEqual(pool['count'], 2); self.assertFalse(pool['worker_chain_tested'])
        self.assertTrue(all(not x['native_proxyip'] for x in pool['candidates']))
        self.assertEqual([x['upstream_type'] for x in pool['candidates']], ['https', 'socks5'])
        self.assertNotIn('candidates', edge_candidates.summary(pool))
