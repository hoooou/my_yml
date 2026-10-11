import copy
from pathlib import Path
import sys
import unittest
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_medium_speed import record
import availability as a
import stability as st


def sample(number, offset=None):
    offset = (number - 1) * 31 if offset is None else offset
    return {'round': number, 'started_offset_seconds': offset, 'finished_offset_seconds': offset + 1,
        'sites': {k: {'status': 'passed', 'elapsed_ms': 100, 'exit_ip': '8.8.8.8'} for k in st.TARGETS},
        'android_tls': {'hostname': st.TLS_HOST, 'status': 'passed', 'tls_version': 'TLSv1.3',
            'elapsed_ms': 100, 'chain_verified': True, 'hostname_verified': True, 'validity_verified': True}}


def evidence():
    return st.summarize([sample(i) for i in range(1, st.ROUNDS + 1)])


class PublicationStabilityTests(unittest.TestCase):
    def test_later_connection_failure_cannot_be_hidden_by_old_download_pass(self):
        row = record()
        row['stability'] = {'status': 'failed', 'reason': 'late_connection_failure'}
        mapping = {row['id']: {'name': row['id'], 'type': 'http', 'server': '8.8.8.8', 'port': 80}}
        result = a.render_comparison({}, [row], mapping)
        self.assertEqual(result['proxies'], [])
        self.assertTrue(all(row.get('name') not in g['proxies'] for g in result['proxy-groups']))

    def test_burst_success_late_failure_and_missing_proof_are_not_published(self):
        row = record()
        mapping = {row['id']: {'name': row['id'], 'type': 'http', 'server': '8.8.8.8', 'port': 80}}
        self.assertEqual(len(a.render_comparison({}, [row], mapping, require_stability=True)['proxies']), 0)
        row['stability'] = evidence()
        self.assertEqual(len(a.render_comparison({}, [row], mapping, require_stability=True)['proxies']), 1)
        row['stability']['attempts'][4]['sites']['Google204']['status'] = 'failed'
        # Even a stale summary saying 'passed' cannot hide a failure.
        self.assertEqual(len(a.render_comparison({}, [row], mapping, require_stability=True)['proxies']), 0)
        row['stability'] = st.summarize([sample(i, i) for i in range(1, 6)])
        self.assertEqual(len(a.render_comparison({}, [row], mapping, require_stability=True)['proxies']), 0)

    def test_rejected_former_name_is_cleared_and_all_groups_remain_manual(self):
        rows = [record('n-a'), record('n-b')]
        rows[0]['stability'] = evidence()
        rows[1]['stability'] = {'status': 'failed'}
        rows[1]['name'] = '美国01|120ms|42Mbps|住宅|纯净度99.2%'
        mapping = {r['id']: {'name': r['id'], 'type': 'http', 'server': '8.8.8.8', 'port': 80} for r in rows}
        cfg = a.render_comparison({}, rows, mapping, require_stability=True)
        self.assertEqual(len(cfg['proxies']), 1)
        self.assertNotIn('name', rows[1])
        self.assertTrue(all(g['type'] == 'select' for g in cfg['proxy-groups']))


class StabilityProbeTests(unittest.TestCase):
    def test_recheck_counts_exclude_historical_failures_and_legacy_summary_can_be_repaired(self):
        fresh = record('n-fresh'); fresh['stability'] = evidence()
        fresh['stability']['updated_at'] = '2026-10-12T04:00:00+08:00'
        old = record('n-old'); old['stability'] = {'status': 'failed', 'updated_at': '2026-10-12T02:00:00+08:00'}
        diag = {'updated_at': '2026-10-12T04:00:00+08:00', 'node_count': 1,
                'controls_valid': True, 'nodes': [{'id': 'n-fresh'}]}
        for current, previous in ((diag, None), (None, {k:v for k,v in diag.items() if k != 'nodes'})):
            info = st.recheck_summary([fresh, old], current, previous, quality=lambda r: True)
            self.assertEqual((info['node_count'], info['passed_count'], info['failed_count']), (1, 1, 0))
            self.assertEqual(info['node_ids'], ['n-fresh'])

    def test_exit_ip_change_is_allowed_but_cert_timeouts_or_missing_rounds_are_not(self):
        good = evidence()
        good['attempts'][3]['sites']['ChatGPTTrace']['exit_ip'] = '1.1.1.1'
        self.assertTrue(st.passed(good))
        for mutation in ('late_timeout', 'unverified', 'missing', 'wrong_host', 'over_budget'):
            bad = copy.deepcopy(good)
            if mutation == 'late_timeout':
                bad['attempts'][4]['sites']['YouTube']['status'] = 'failed'
            elif mutation == 'unverified':
                bad['attempts'][4]['android_tls']['chain_verified'] = False
            elif mutation == 'wrong_host':
                bad['attempts'][4]['android_tls']['hostname'] = 'wrong.example'
            elif mutation == 'over_budget':
                bad['attempts'][4]['sites']['ChatGPTTrace']['elapsed_ms'] = 5001
            else:
                bad['attempts'].pop()
            self.assertFalse(st.passed(bad), mutation)

    def test_late_slow_core_sample_removes_strict_node_even_if_every_request_succeeds(self):
        row = record()
        row['stability'] = evidence()
        row['stability']['attempts'][4]['sites']['YouTube']['elapsed_ms'] = 3100
        self.assertTrue(st.passed(row['stability']))
        self.assertFalse(a.web_quality_eligible(row))
        self.assertFalse(st.quality_passed(row['stability'], 1500, 3000, 1500))

    def test_live_caller_measures_serial_requests_and_verified_tls(self):
        with patch.object(st, 'check_site', side_effect=lambda port, label, url: {'status': 'passed', 'elapsed_ms': 100}) as check, \
             patch.object(st.app_tls, 'probe', return_value=sample(1)['android_tls']) as tls, \
             patch.object(st.time, 'monotonic', side_effect=[10, 11]):
            result = st.sample_node(1234, 1, 0)
        self.assertEqual([call.args[1] for call in check.call_args_list], list(st.TARGETS))
        tls.assert_called_once_with(1234, st.TLS_HOST)
        self.assertTrue(st.round_passed(result))

    def test_failed_round_stops_extra_requests_but_next_round_retries_all_targets(self):
        with patch.object(st, 'check_site', return_value={'status': 'failed', 'elapsed_ms': 3000}) as check, \
             patch.object(st.app_tls, 'probe') as tls:
            first = st.sample_node(1234, 1, 0)
        self.assertEqual(check.call_count, 1)
        tls.assert_not_called()
        self.assertEqual(first['sites']['YouTube']['status'], 'skipped')
        with patch.object(st, 'check_site', return_value={'status': 'passed', 'elapsed_ms': 100}) as check, \
             patch.object(st.app_tls, 'probe', return_value=sample(1)['android_tls']) as tls:
            next_round = st.sample_node(1234, 2, 0)
        self.assertEqual(check.call_count, 4)
        self.assertTrue(st.round_passed(next_round))
        partial = st.summarize([first])
        self.assertEqual(partial['status'], 'incomplete')
        self.assertEqual([x['target'] for x in partial['failures']], ['Google204'])
        self.assertFalse(st.passed(partial))

    def test_runner_repeats_every_candidate_waits_after_round_and_aborts_on_bad_control(self):
        class Clock:
            value = 0
            def now(self): return self.value
            def sleep(self, seconds): self.value += seconds
        for control_ok, core_ok in ((True, True), (False, True), (True, False)):
            clock = Clock()
            rows = [record('n-a'), record('n-b')]
            def probe(port, number, origin):
                result = sample(number, clock.value)
                result['finished_offset_seconds'] = clock.value
                if port == 1235 and number == 5:
                    result['sites']['YouTube']['status'] = 'failed'
                return result
            control = {'sites': {'Google204': {'status': 'passed' if control_ok else 'failed'}},
                       'android_tls': sample(1)['android_tls']}
            with tempfile.TemporaryDirectory() as directory, patch.object(st.s, 'Core'), \
                 patch.object(st.s, 'make_listeners', return_value=([], {'n-a': 1234, 'n-b': 1235})), \
                 patch.object(st, 'sample_node', side_effect=probe) as measure, \
                 patch.object(st, 'sample_control', return_value=control), \
                 patch.object(st, 'core_health', return_value={'process_alive': core_ok, 'api_available': core_ok, 'file_limit_errors': 0}), \
                 patch.object(st.time, 'monotonic', side_effect=clock.now), \
                 patch.object(st.time, 'sleep', side_effect=clock.sleep) as sleep:
                if control_ok and core_ok:
                    result = st.recheck(rows, {'n-a': {}, 'n-b': {}}, 'unused', Path(directory))
                    self.assertTrue(st.passed(rows[0]['stability']))
                    self.assertFalse(st.passed(rows[1]['stability']))
                    self.assertEqual(result['node_count'], 2)
                else:
                    with self.assertRaisesRegex(RuntimeError, '对照异常'):
                        st.recheck(rows, {'n-a': {}, 'n-b': {}}, 'unused', Path(directory))
                    self.assertNotIn('stability', rows[0])
                self.assertEqual(measure.call_count, 10)
                self.assertEqual(sleep.call_count, 4)
                self.assertGreaterEqual(clock.value, 120)
                self.assertTrue((Path(directory) / 'stability-results.json').exists())


if __name__ == '__main__':
    unittest.main()
