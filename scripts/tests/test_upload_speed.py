import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import upload_speed as up
from tls_fixture import verified_tls
import availability as a
import mobile_pilot
import os
os.environ.setdefault('CHAIN_EXTERNAL_SUB', 'off')  # 测试不联网拉自有订阅


def sample(byte_count=up.BYTES, budget=up.BUDGET, elapsed=1000):
    return {'version': up.VERSION, 'status': 'passed', 'url': up.url(byte_count),
            'effective_url': up.url(byte_count), 'requested_bytes': byte_count,
            'uploaded_bytes': byte_count, 'budget_seconds': budget, 'elapsed_ms': elapsed,
            'speed_mbps': byte_count * 8 / (elapsed / 1000) / 1_000_000,
            'curl_exit_code': 0, 'http_status': 200, 'redirect_count': 0,
            'ssl_verify_result': 0, 'tls_verification_enabled': True, 'http_completed': True,
            'loaded_204': [{'status': 'passed', 'elapsed_ms': 100}]}


def evidence():
    return up.summarize(sample(up.PRECHECK_BYTES, up.PRECHECK_BUDGET),
                        [sample(), sample(elapsed=2000)], up.GAP_SECONDS)


class UploadTests(unittest.TestCase):
    def test_optional_website_certificate_error_is_not_hidden_by_other_successes(self):
        from test_medium_speed import record
        row = record()
        row['websites']['Netflix']['attempts'] = [{'status': 'failed',
            'tls_error_kind': 'certificate_verification_failed'}]
        self.assertFalse(a.web_quality_eligible(row))
        row['exit']['country_code'] = 'SG'; self.assertFalse(a.regional_eligible(row))
        wrapped = a.s.requests.exceptions.SSLError('[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: private data')
        self.assertTrue(mobile_pilot.certificate_failure(wrapped))
        self.assertFalse(mobile_pilot.certificate_failure(a.s.requests.exceptions.SSLError('TLS EOF')))

    def test_full_publication_runs_upload_before_final_stability_and_persists_gate(self):
        from test_medium_speed import record
        from test_stability import evidence as stable_evidence
        row = record(); row.update(server='8.8.8.8', port=443, protocol='ss')
        row['precheck'] = a.summarize_rounds([{'Google204': {'status': 'passed', 'elapsed_ms': 100}}]*3, ('Google204',))['Google204']
        node = {'name': row['id'], 'type': 'ss', 'server': '8.8.8.8', 'port': 443, 'cipher': 'aes-128-gcm', 'password': 'test-password'}
        bundle = {'nodes': [node], 'base': {}, 'metadata': {}, 'sources': [], 'input_count': 1,
                  'rejected': [], 'services': {}, 'scope': 'all_subscriptions', 'id': 'batch'}
        calls = []
        def upload(rows, *_, **kwargs):
            calls.append('upload')
            self.assertTrue(kwargs['reuse_precheck'])
            self.assertEqual([r['id'] for r in rows], [row['id']])
            row['upload'] = evidence(); row['post_upload_tls'] = verified_tls()
            return {'updated_at': '2026-10-12T06:00:00+08:00', 'node_count': 1, 'controls_valid': True,
                    'nodes': [{'id': row['id'], 'upload': row['upload']}]}
        def stable(rows, *_):
            calls.append('stability'); self.assertTrue(up.passed(rows[0]['upload']))
            row['stability'] = stable_evidence()
            return {'updated_at': '2026-10-12T06:00:00+08:00', 'node_count': 1, 'controls_valid': True,
                    'nodes': [{'id': row['id']}]}
        with tempfile.TemporaryDirectory() as folder:
            cwd = os.getcwd()
            try:
                os.chdir(folder); root = Path('.node-work/availability'); root.mkdir(parents=True)
                (root / 'bundle.json').write_text(json.dumps(bundle))
                with patch.object(sys, 'argv', ['availability', '--phase', 'publish', '--mihomo', 'unused']), \
                     patch.object(a, 'merge_shards', return_value=([row], 1)), \
                     patch.object(a.s, 'lookup_ip_types', return_value={}), \
                     patch.object(a.ip_reputation, 'lookup', return_value={}), \
                     patch.object(a.upload_speed, 'recheck', side_effect=upload), \
                     patch.object(a.stability, 'recheck', side_effect=stable), \
                     patch.object(a.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    a.main()
                self.assertEqual(calls, ['upload', 'stability'])
                report = json.loads(Path('连通性报告.json').read_text())
                self.assertTrue(report['node_selection_policy']['requires_uplink_pass'])
                self.assertEqual(report['published_node_count'], 1)
                self.assertEqual(report['upload_recheck']['node_ids'], [row['id']])
                self.assertEqual(report['domestic_target_count'], 0)
                self.assertIn('upload_double', report['stages'])
            finally:
                os.chdir(cwd)

    def test_upload_or_post_load_certificate_failure_removes_node_from_all_groups(self):
        from test_medium_speed import record
        from test_stability import evidence as stable_evidence
        row = record(); row['stability'] = stable_evidence()
        mapping = {row['id']: {'name': row['id'], 'type': 'http', 'server': '8.8.8.8', 'port': 80}}
        self.assertEqual(a.render_comparison({}, [row], mapping, require_upload=True)['proxies'], [])
        row['upload'] = evidence(); row['post_upload_tls'] = verified_tls()
        self.assertEqual(len(a.render_comparison({}, [row], mapping, require_upload=True)['proxies']), 1)
        row['upload']['attempts'][1]['uploaded_bytes'] -= 1
        self.assertEqual(a.render_comparison({}, [row], mapping, require_upload=True)['proxies'], [])
        row['upload'] = evidence()
        row['post_upload_tls']['targets']['chatgpt.com']['attempts'][0]['hostname_verified'] = False
        self.assertEqual(a.render_comparison({}, [row], mapping, require_upload=True)['proxies'], [])

    def test_similar_response_band_prefers_balanced_upload_over_download_only(self):
        from test_medium_speed import record
        from test_stability import evidence as stable_evidence
        first = record('n-down-only'); first['stability'] = stable_evidence(); first['upload'] = evidence()
        first['upload'] = up.summarize(first['upload']['precheck'], [sample(elapsed=9000)] * 2, 20)
        second = record('n-balanced'); second['stability'] = stable_evidence(); second['upload'] = evidence()
        for attempt in second['stability']['attempts']:
            for label in ('Google', 'YouTube'): attempt['sites'][label]['elapsed_ms'] += 30
        self.assertLess(a.rank_key(second), a.rank_key(first))

    def test_daily_targets_omit_domestic_pages_without_losing_routing_or_traces(self):
        from routing import optimize_routing
        self.assertFalse(set(a.DAILY_POST_SITES) & set(a.DOMESTIC_SITES))
        self.assertTrue(set(a.REQUIRED_SITES) | set(a.REQUIRED_TRACES) <= set(a.DAILY_POST_SITES))
        cfg = {}; optimize_routing(cfg)
        self.assertIn('RULE-SET,domestic-services,DIRECT', cfg['rules'])
        self.assertIn('+.bilibili.com', cfg['rule-providers']['domestic-services']['payload'])

    def test_complete_two_rounds_take_lower_speed_and_recompute_evidence(self):
        good = evidence(); self.assertTrue(up.passed(good))
        self.assertEqual(good['speed_mbps'], 20)
        for field, value in [('uploaded_bytes', up.BYTES - 1), ('ssl_verify_result', 60),
                             ('http_status', 403), ('redirect_count', 1),
                             ('tls_verification_enabled', False), ('http_completed', False),
                             ('elapsed_ms', 10001), ('speed_mbps', float('nan'))]:
            bad = copy.deepcopy(good); bad['attempts'][1][field] = value
            self.assertFalse(up.passed(bad), field)
        bad = copy.deepcopy(good); bad['idle_seconds'] = 0; self.assertFalse(up.passed(bad))
        bad = copy.deepcopy(good); bad['attempts'].pop(); self.assertFalse(up.passed(bad))
        bad = copy.deepcopy(good); bad['speed_mbps'] = 100; self.assertFalse(up.passed(bad))
        bad = copy.deepcopy(good); bad['attempts'][1]['loaded_204'][0]['status'] = 'failed'
        self.assertFalse(up.passed(bad))
        bad = copy.deepcopy(good); bad['attempts'][1]['loaded_204'] = []
        self.assertFalse(up.passed(bad))

    def test_real_curl_caller_checks_full_post_and_never_disables_certificate_validation(self):
        def run(command, **kwargs):
            self.assertEqual(command[:2], ['curl', '--disable'])
            self.assertNotIn('--insecure', command); self.assertNotIn('-k', command)
            self.assertNotIn('--location', command)
            self.assertIn('--cacert', command); self.assertIn('--max-time', command)
            self.assertEqual(command[command.index('--proxy') + 1], 'http://127.0.0.1:1234')
            payload = Path(command[command.index('--data-binary') + 1][1:])
            self.assertEqual(payload.stat().st_size, up.BYTES)
            Path(command[command.index('--output') + 1]).write_bytes(b'ok')
            return subprocess.CompletedProcess(command, 0, json.dumps({'time_total': 1,
                'http_code': 200, 'url_effective': up.url(up.BYTES), 'size_upload': up.BYTES,
                'ssl_verify_result': 0, 'num_redirects': 0}), '')
        with patch.object(up.subprocess, 'run', side_effect=run):
            self.assertTrue(up.sample_passed(up.sample(1234)))

    def test_tls_failure_timeout_and_early_response_are_not_upload_success(self):
        for code, sent, expected in ((60, 0, 'certificate_verification_failed'),
                                     (28, 1000, 'timeout'), (0, 1000, None)):
            output = json.dumps({'time_total': 1, 'http_code': 200, 'url_effective': up.url(up.BYTES),
                'size_upload': sent, 'ssl_verify_result': code if code == 60 else 0, 'num_redirects': 0})
            with patch.object(up.subprocess, 'run', return_value=subprocess.CompletedProcess([], code, output, '')):
                result = up.sample(1234)
            self.assertEqual(result['status'], 'failed')
            if expected: self.assertEqual(result['error_type'], expected)
        with patch.object(up.subprocess, 'run', side_effect=subprocess.TimeoutExpired([], 13)):
            self.assertEqual(up.sample(1234)['error_type'], 'process_deadline')

    def test_early_upload_caller_sends_3mb_with_six_second_total_deadline(self):
        def run(command, **kwargs):
            self.assertEqual(command[-1], 'https://speed.cloudflare.com/__up?bytes=3000000')
            self.assertEqual(command[command.index('--max-time') + 1], '6')
            payload = Path(command[command.index('--data-binary') + 1][1:])
            self.assertEqual(payload.stat().st_size, 3_000_000)
            self.assertNotIn('--insecure', command)
            return subprocess.CompletedProcess(command, 0, json.dumps({'time_total': 6,
                'http_code': 200, 'url_effective': command[-1], 'size_upload': 3_000_000,
                'ssl_verify_result': 0, 'num_redirects': 0}), '')
        with patch.object(up.subprocess, 'run', side_effect=run):
            result = up.sample(1234, up.PRECHECK_BYTES, up.PRECHECK_BUDGET)
        self.assertTrue(up.sample_passed(result, 3_000_000, 6))
        self.assertEqual(result['speed_mbps'], 4)

    def test_failed_precheck_skips_bandwidth_rounds_and_failed_first_round_still_retests(self):
        with patch.object(up, 'sample', return_value={'status': 'failed'}), patch.object(up, 'loaded_sample') as probe:
            self.assertFalse(up.passed(up.check(1234))); probe.assert_not_called()
        with patch.object(up, 'sample', return_value=sample(up.PRECHECK_BYTES, up.PRECHECK_BUDGET)), \
             patch.object(up, 'loaded_sample', side_effect=[{'status': 'failed'}, sample()]) as probe, \
             patch.object(up.time, 'sleep'), patch.object(up.time, 'monotonic', side_effect=[0, 20]):
            result = up.check(1234)
        self.assertEqual(probe.call_count, 2); self.assertFalse(up.passed(result))

    def test_bad_runner_control_aborts_before_any_publication(self):
        for control_ok in (True, False):
            records = [{'id': 'n-a'}]
            checks = [evidence(), evidence(), evidence() if control_ok else {'status': 'failed'}]
            with tempfile.TemporaryDirectory() as root, patch.object(up.s, 'Core'), \
                 patch.object(up.s, 'make_listeners', return_value=([], {'n-a': 1234})), \
                 patch.object(up, 'check', side_effect=checks), \
                 patch.object(up.app_tls, 'check', return_value=verified_tls()), \
                 patch('stability.core_health', return_value={'process_alive': True, 'api_available': True, 'file_limit_errors': 0}):
                if control_ok:
                    result = up.recheck(records, {'n-a': {}}, 'unused', root)
                    self.assertTrue(result['controls_valid'])
                else:
                    with self.assertRaisesRegex(RuntimeError, '对照异常'):
                        up.recheck(records, {'n-a': {}}, 'unused', root)
                self.assertTrue((Path(root) / 'upload-results.json').exists())


if __name__ == '__main__':
    unittest.main()
