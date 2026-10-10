import copy
from pathlib import Path
import sys
import unittest
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a
import mobile_pilot as p


class WebQualityTests(unittest.TestCase):
    def test_successful_but_slow_response_is_not_a_fast_pass(self):
        class Response:
            status_code = 200
            url = p.SITES['YouTube']
            headers = {'Content-Type': 'text/html'}
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def iter_content(self, size): return iter([b'<html>YouTube</html>'])
        with patch.object(p.s, 'session') as session, patch.object(p.time, 'perf_counter', side_effect=[0] + [8]*20):
            session.return_value.__enter__.return_value.get.return_value = Response()
            result = p.check_site(1234, 'YouTube', p.SITES['YouTube'])
        self.assertEqual(result['status'], 'slow')
        self.assertEqual(result['ttfb_ms'], 8000)
        self.assertGreaterEqual(result['elapsed_ms'], 8000)

    def test_three_rounds_report_tail_jitter_and_timeouts_without_hiding_failures(self):
        rounds = [{'YouTube': {'status': 'passed', 'elapsed_ms': x, 'ttfb_ms': x - 10}}
                  for x in (100, 110, 120)]
        result = a.summarize_rounds(rounds, ('YouTube',))['YouTube']
        self.assertEqual(result['p95_elapsed_ms'], 120)
        self.assertEqual(result['jitter_ms'], 20)
        self.assertEqual(result['median_ttfb_ms'], 100)
        rounds[2]['YouTube'] = {'status': 'failed', 'elapsed_ms': 5000, 'reason': 'timeout'}
        result = a.summarize_rounds(rounds, ('YouTube',))['YouTube']
        self.assertEqual(result['p95_elapsed_ms'], 5000)
        self.assertEqual(result['failure_count'], 1)
        self.assertEqual(result['status'], 'unstable')
        self.assertAlmostEqual(result['success_rate'], 2/3, places=4)

    def test_recheck_only_updates_passed_pool_and_preserves_tcp_download_and_trace(self):
        records = [{'id': 'n-' + str(i), 'entry': {'status': 'passed'},
            'download': {'status': status, 'speed_mib_s': 5}, 'high_speed_download': {'status': 'passed'},
            'websites': {'ClaudeTrace': {'status': 'passed', 'round_count': 1}},
            'precheck': {'status': 'passed'}} for i, status in enumerate(('passed', 'failed', 'skipped'))]
        old = copy.deepcopy(records)
        result = {label: {'status': 'passed', 'elapsed_ms': 100, 'ttfb_ms': 90} for label in a.OVERSEAS_SITES}
        with tempfile.TemporaryDirectory() as directory, patch.object(a.s, 'Core'), patch.object(a.s, 'make_listeners', return_value=([], {'n-0': 1234})) as listeners, \
             patch.object(a, 'check_sites', return_value=result) as check:
            self.assertEqual(a.recheck_websites(records, {'n-0': {'name': 'n-0'}}, 'unused', Path(directory)), 1)
        self.assertEqual([r['id'] for r in listeners.call_args.args[0]], ['n-0'])
        self.assertEqual(check.call_count, 3)
        self.assertEqual(records[0]['websites']['YouTube']['round_count'], 3)
        for field in ('entry', 'download', 'high_speed_download', 'precheck'):
            self.assertEqual(records[0][field], old[0][field])
        self.assertEqual(records[0]['websites']['ClaudeTrace'], old[0]['websites']['ClaudeTrace'])
        self.assertEqual(records[1:], old[1:])

    def test_real_website_latency_precedes_204_and_download_speed_in_ranking(self):
        sites = {label: {'status': 'passed', 'round_count': 3, 'passed_count': 3,
            'median_elapsed_ms': 100, 'p95_elapsed_ms': 110, 'jitter_ms': 10}
            for label in a.OVERSEAS_SITES}
        fast = {'id': 'n-fast', 'entry': {'status': 'passed'}, 'websites': sites,
            'precheck': {'status': 'passed', 'median_elapsed_ms': 300},
            'download': {'status': 'passed', 'speed_mib_s': 2}}
        slow = copy.deepcopy(fast); slow['id'] = 'n-slow'
        slow['precheck']['median_elapsed_ms'] = 1
        slow['download']['speed_mib_s'] = 100
        for item in slow['websites'].values():
            item.update(median_elapsed_ms=2500, p95_elapsed_ms=4500, jitter_ms=3000)
        self.assertLess(a.rank_key(fast), a.rank_key(slow))

    def test_single_round_trace_or_failed_youtube_cannot_qualify_for_preferred_group(self):
        sites = {label: {'status': 'passed', 'round_count': 3, 'passed_count': 3,
            'median_elapsed_ms': 100, 'p95_elapsed_ms': 120, 'jitter_ms': 20}
            for label in a.OVERSEAS_SITES}
        record = {'id': 'n-a', 'entry': {'status': 'passed'}, 'websites': sites,
            'download': {'status': 'passed', 'speed_mib_s': 10}}
        self.assertTrue(a.web_quality_eligible(record))
        for changed in ('failed', 'single', 'slow'):
            bad = copy.deepcopy(record)
            if changed == 'single':
                bad['websites']['YouTube'].update(round_count=1, passed_count=1)
            elif changed == 'slow':
                bad['websites']['YouTube'].update(p95_elapsed_ms=5001)
            else:
                bad['websites']['YouTube']['status'] = 'failed'
            self.assertFalse(a.web_quality_eligible(bad))
