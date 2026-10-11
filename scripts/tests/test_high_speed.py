import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a
from medium_speed_fixture import verified_medium
import high_speed
from high_speed_fixture import verified_high
from tls_fixture import verified_tls


class DoubleDownloadTests(unittest.TestCase):
    def setUp(self):
        medium = patch.object(a, 'medium_speed_download', side_effect=lambda port: verified_medium())
        medium.start(); self.addCleanup(medium.stop)

    def test_cloudflare_100mb_request_supplies_required_speed_site_referer(self):
        class Response:
            url = high_speed.URLS[0]
            headers = {'Content-Length': str(high_speed.BYTES), 'Content-Type': 'application/octet-stream'}
            def __init__(self, allowed):
                self.status_code = 200 if allowed else 403
                self.raw = self
                self.remaining = high_speed.BYTES
            def read1(self, size):
                count = min(size, self.remaining); self.remaining -= count
                return b'x' * count
            def __enter__(self): return self
            def __exit__(self, *args): pass
        def fetch(url, **kwargs):
            return Response(kwargs['headers'].get('Referer') == 'https://speed.cloudflare.com/')
        with patch.object(a.s, 'session') as session, \
             patch.object(a.time, 'perf_counter', side_effect=[0] + [2] * 7000):
            session.return_value.__enter__.return_value.get.side_effect = fetch
            result = a.download_sample(1234, high_speed.BYTES, high_speed.BUDGET, high_speed.URLS[0])
        self.assertEqual(result['status'], 'passed')

    def test_pipeline_uses_both_targets_with_independent_deadlines_after_quick_pass(self):
        node = {'name': 'n-a', 'type': 'ss', 'server': '8.8.8.8', 'port': 443}
        samples = verified_high(10)['attempts']
        with patch.object(a.s, 'Core'), patch.object(a.s, 'query_exit', return_value=None), \
             patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1234})), \
             patch.object(a.app_tls, 'check', return_value=verified_tls()), \
             patch.object(a, 'download_sample', side_effect=samples) as measure:
            records, _ = a.probe_pipeline([node], 'unused', Path('.'),
                precheck=lambda port: {'status': 'passed'}, probe=lambda key, pace: {'status': 'passed'},
                site_check=lambda port: {label: {'status': 'passed', 'elapsed_ms': 10} for label in a.POST_SITES},
                download=lambda port: {'status': 'passed'})
        self.assertEqual([call.args for call in measure.call_args_list],
            [(1234, 100_000_000, 20, url) for url in high_speed.URLS])
        self.assertTrue(a.high_speed_eligible(records[0]))

    def test_one_failure_still_records_both_targets_and_blocks_only_high_speed(self):
        from test_availability import AvailabilityTests
        for failed_index in (0, 1):
            samples = verified_high()['attempts']
            samples[failed_index].update(status='failed', received_bytes=12, speed_mib_s=None)
            with patch.object(a, 'download_sample', side_effect=samples) as measure:
                result = a.high_speed_download(1234)
            self.assertEqual(measure.call_count, 2)
            self.assertEqual(result['passed_count'], 1)
            self.assertEqual(result['status'], 'failed')
            self.assertIsNone(result['speed_mib_s'])
            record = {'id': 'n-a', 'app_tls': verified_tls(), 'entry': {'status': 'passed'},
                'websites': AvailabilityTests.stable_sites(), 'download': {'status': 'passed', 'speed_mib_s': 1},
                'high_speed_download': result, 'exit': None}
            config = a.render_comparison({}, [record],
                {'n-a': {'name': 'n-a', 'type': 'http', 'server': '8.8.8.8', 'port': 80}})
            groups = {g['name']: g['proxies'] for g in config['proxy-groups']}
            self.assertEqual(groups['⚡ 高速下载'], ['REJECT'])
            self.assertEqual(groups['⭐ 综合优选'], [record['name']])

    def test_bottleneck_speed_and_complete_evidence_required(self):
        samples = [verified_high(20)['attempts'][0], verified_high(5)['attempts'][1]]
        result = high_speed.summarize(samples)
        self.assertTrue(high_speed.passed(result))
        self.assertEqual(result['speed_mib_s'], 5)
        self.assertEqual(high_speed.result_counts([{'high_speed_download': samples[0]}])['passed'], 0)
        self.assertEqual(high_speed.result_counts([{'high_speed_download': samples[0]}])['unverified'], 1)
        for mutation in ('missing_round', 'same_url', 'old_50mb', 'over_time', 'partial', 'fake_speed', 'fake_summary'):
            bad = copy.deepcopy(result)
            second = bad['attempts'][1]
            if mutation == 'missing_round': bad['attempts'].pop()
            elif mutation == 'same_url': second['url'] = high_speed.URLS[0]
            elif mutation == 'old_50mb': second.update(requested_bytes=50_000_000, received_bytes=50_000_000)
            elif mutation == 'over_time': second['elapsed_ms'] = 20001
            elif mutation == 'partial': second['received_bytes'] -= 1
            elif mutation == 'fake_speed': second['speed_mib_s'] = 500
            else: bad['speed_mib_s'] = 20
            self.assertFalse(high_speed.passed(bad), mutation)

    def test_each_target_rejects_wrong_length_type_redirect_and_partial_response(self):
        class Raw:
            def __init__(self, count): self.remaining = count
            def read1(self, size):
                length = min(size, self.remaining); self.remaining -= length
                return b'x' * length
        class Response:
            status_code = 200
            def __init__(self, url, case):
                self.url = url
                self.headers = {'Content-Length': str(high_speed.BYTES), 'Content-Type': 'application/octet-stream'}
                self.raw = Raw(high_speed.BYTES - (case == 'partial'))
                if case == 'redirect': self.status_code = 302
                elif case == 'short_header': self.headers['Content-Length'] = '50000000'
                elif case == 'html': self.headers['Content-Type'] = 'text/html'
            def __enter__(self): return self
            def __exit__(self, *args): pass
        for url in high_speed.URLS:
            for case in ('normal', 'partial', 'redirect', 'short_header', 'html'):
                with patch.object(a.s, 'session') as session, \
                     patch.object(a.time, 'perf_counter', side_effect=[0] + [2] * 7000):
                    session.return_value.__enter__.return_value.get.return_value = Response(url, case)
                    result = a.download_sample(1234, high_speed.BYTES, high_speed.BUDGET, url)
                self.assertEqual(result['status'], 'passed' if case == 'normal' else 'failed', (url, case))
                self.assertEqual(result['url'], url)


if __name__ == '__main__':
    unittest.main()
