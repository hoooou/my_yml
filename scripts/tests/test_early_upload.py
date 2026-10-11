import concurrent.futures as futures
import copy
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a
import upload_speed as up
from bandwidth_gate import BandwidthGate
from upload_fixture import verified_upload_precheck
from test_upload_speed import sample
from tls_fixture import verified_tls


class EarlyUploadTests(unittest.TestCase):
    def pipeline(self, early, controls, sites=None, tcp='passed'):
        node = {'name': 'n-a', 'type': 'ss', 'server': '8.8.8.8', 'port': 443}
        pre = a.summarize_rounds([{'Google204': {'status': 'passed', 'elapsed_ms': 1}}]*3, ('Google204',))['Google204']
        sites = sites or (lambda p: {k: {'status': 'passed', 'elapsed_ms': 1} for k in a.POST_SITES})
        with patch.object(a.s, 'Core'), patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1234})), \
             patch.object(a.s, 'query_exit', return_value=None), patch.object(a.app_tls, 'check', return_value=verified_tls()):
            records, endpoints = a.probe_pipeline([node], 'unused', Path('.'),
                precheck=lambda p: pre, probe=lambda k, pace: {'status': tcp},
                upload_precheck=early, upload_controls=controls, site_check=sites,
                download=lambda p: {'status': 'failed'})
        return {'id': 'batch', 'nodes': [node], 'early_upload_precheck': True}, {
            'bundle_id': 'batch', 'index': 0, 'count': 1, 'endpoint_count': endpoints,
            'records': records, 'upload_precheck_controls': controls}

    def test_precheck_failure_preserves_tcp_pass_and_skips_websites_and_downloads(self):
        for bad in ({'status': 'failed'}, {**verified_upload_precheck(), 'uploaded_bytes': 1}):
            def early(port): return verified_upload_precheck() if port is None else bad
            with patch.object(a, 'check_sites') as sites:
                # Custom callable makes an accidental website call observable.
                bundle, part = self.pipeline(early, {}, sites=sites)
                sites.assert_not_called()
            row = part['records'][0]
            self.assertEqual(row['entry']['status'], 'passed')
            self.assertIsNone(row['websites']); self.assertEqual(row['download']['status'], 'skipped')
            if bad['status'] == 'failed':
                a.merge_shards(bundle, [part], 1)
            else:
                with self.assertRaisesRegex(ValueError, '预检证据'):
                    a.merge_shards(bundle, [part], 1)

    def test_order_before_websites_controls_and_merge_reject_forged_early_results(self):
        events = []
        def early(port):
            events.append(('upload', port)); return verified_upload_precheck()
        def sites(port):
            self.assertIn(('upload', port), events)
            events.append(('websites', port))
            return {k: {'status': 'passed', 'elapsed_ms': 1} for k in a.POST_SITES}
        bundle, part = self.pipeline(early, {}, sites)
        self.assertEqual(events[0], ('upload', None)); self.assertEqual(events[-1], ('upload', None))
        a.merge_shards(bundle, [part], 1)
        for change in ('missing', 'late', 'bad_control', 'bypassed_failure'):
            bad = copy.deepcopy(part)
            if change == 'missing': bad['records'][0].pop('upload_precheck')
            elif change == 'late': bad['records'][0]['upload_precheck']['elapsed_ms'] = 6001
            elif change == 'bad_control': bad['upload_precheck_controls']['after']['ssl_verify_result'] = 60
            else: bad['records'][0]['upload_precheck']['status'] = 'failed'
            with self.assertRaises(ValueError, msg=change): a.merge_shards(bundle, [bad], 1)

    def test_tcp_failure_never_uploads_and_direct_control_failure_aborts(self):
        with patch.object(up, 'sample') as sampler:
            bundle, part = self.pipeline(sampler, {}, tcp='failed')
            sampler.assert_not_called(); a.merge_shards(bundle, [part], 1)
        for fail_after in (False, True):
            controls = {}; calls = []
            def early(port):
                calls.append(port)
                return {'status': 'failed'} if port is None and (not fail_after or calls.count(None) == 2) else verified_upload_precheck()
            with self.assertRaisesRegex(RuntimeError, '对照异常'):
                self.pipeline(early, controls)
            self.assertFalse(controls['valid'])

    def test_precheck_failure_cannot_use_old_web_or_upload_pass_to_be_published(self):
        from test_medium_speed import record
        row = record()
        row['upload_precheck'] = {'status': 'failed'}
        self.assertFalse(a.web_quality_eligible(row))
        row['exit']['country_code'] = 'SG'
        self.assertFalse(a.regional_eligible(row))

    def test_empty_shard_is_valid_without_upload_controls(self):
        controls = {}
        self.assertEqual(a.probe_pipeline([], 'unused', Path('.'), upload_controls=controls), ([], 0))
        self.assertTrue(controls['valid']); self.assertIsNone(controls['before'])

    def test_final_upload_reuses_only_supplied_precheck_and_does_not_repeat_1mb(self):
        first = verified_upload_precheck()
        with patch.object(up, 'sample') as fetch, patch.object(up, 'loaded_sample', side_effect=[sample(), sample()]) as loaded, \
             patch.object(up.time, 'sleep'), patch.object(up.time, 'monotonic', side_effect=[0, 20]):
            result = up.check(1234, precheck=first)
        self.assertTrue(up.passed(result)); self.assertEqual(loaded.call_count, 2)
        self.assertEqual(result['precheck'], first); fetch.assert_not_called()
        with patch.object(up, 'sample') as fetch, patch.object(up, 'loaded_sample') as loaded:
            self.assertFalse(up.passed(up.check(1234, precheck={'status': 'failed'})))
            fetch.assert_not_called(); loaded.assert_not_called()

    def test_same_runner_upload_and_download_never_overlap_and_exception_releases_gate(self):
        gate = BandwidthGate(); attempted = threading.Event(); entered = threading.Event()
        def download():
            attempted.set()
            with gate.download(): entered.set()
        with futures.ThreadPoolExecutor(max_workers=1) as pool:
            with gate.upload():
                job = pool.submit(download)
                self.assertTrue(attempted.wait(1)); self.assertFalse(entered.wait(.03))
            job.result(timeout=1); self.assertTrue(entered.is_set())
        with self.assertRaises(RuntimeError):
            with gate.download(): raise RuntimeError('fixture')
        with gate.upload(): self.assertEqual(gate.downloads, 0)

    def test_gate_keeps_parallel_downloads_and_serializes_uploads(self):
        gate = BandwidthGate(); barrier = threading.Barrier(2)
        def download():
            with gate.download(): barrier.wait(1)
        with futures.ThreadPoolExecutor(max_workers=2) as pool:
            tasks = [pool.submit(download) for _ in range(2)]
            for task in tasks: task.result(timeout=2)
        attempted = threading.Event(); entered = threading.Event()
        def upload():
            attempted.set()
            with gate.upload(): entered.set()
        with futures.ThreadPoolExecutor(max_workers=1) as pool:
            with gate.upload():
                task = pool.submit(upload); self.assertTrue(attempted.wait(1))
                self.assertFalse(entered.wait(.03))
            task.result(timeout=1); self.assertTrue(entered.is_set())
