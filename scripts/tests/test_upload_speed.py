import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import upload_speed as up


def sample(byte_count=up.BYTES, budget=up.BUDGET, elapsed=1000):
    return {'version': up.VERSION, 'status': 'passed', 'url': up.url(byte_count),
            'effective_url': up.url(byte_count), 'requested_bytes': byte_count,
            'uploaded_bytes': byte_count, 'budget_seconds': budget, 'elapsed_ms': elapsed,
            'speed_mbps': byte_count * 8 / (elapsed / 1000) / 1_000_000,
            'curl_exit_code': 0, 'http_status': 200, 'redirect_count': 0,
            'ssl_verify_result': 0, 'tls_verification_enabled': True, 'http_completed': True}


def evidence():
    return up.summarize(sample(up.PRECHECK_BYTES, up.PRECHECK_BUDGET),
                        [sample(), sample(elapsed=2000)], up.GAP_SECONDS)


class UploadTests(unittest.TestCase):
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
