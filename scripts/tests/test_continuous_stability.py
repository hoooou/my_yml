import copy
import concurrent.futures as futures
import json
import os
import subprocess
import threading
import time
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a
import continuous_stability as cs
import stability as st
import detection_report as d
from test_stability import sample
from test_medium_speed import record
from upload_fixture import verified_upload_precheck
from test_upload_speed import evidence as upload_evidence
from tls_fixture import verified_tls
from test_detection_report import fixture, render


def evidence(failures=0, cutoff=0):
    attempts = [sample(i, (i-1)*30) for i in range(1, 21)]
    for item in attempts[:failures]:
        item['sites']['Google204'].update(status='failed', elapsed_ms=3001)
        for k in ('Google', 'YouTube', 'ChatGPTTrace'):
            item['sites'][k]['status'] = 'skipped'
        item['android_tls']['status'] = 'skipped'
    return cs.summarize(attempts, cutoff)


def observation(bundle, rows):
    return {'bundle_id': bundle['id'], 'index': 0, 'count': 1, 'diagnostic': {
        'settings': cs.settings(), 'updated_at': '2026-10-12T08:00:00+08:00', 'complete': True, 'controls_valid': True,
        'node_count': len(rows), 'nodes': [{'id': r['id'], 'stability': evidence()} for r in rows],
        'controls': [{'sites': {'Google204': {'status': 'passed', 'elapsed_ms': 10}},
                      'android_tls': sample(1)['android_tls'], 'started_offset_seconds': i*60, 'finished_offset_seconds': i*60+1} for i in range(11)],
        'core_health': [{'process_alive': True, 'api_available': True}]}}


class EvidenceTests(unittest.TestCase):
    def test_ninety_percent_keeps_two_transient_failures_but_not_three(self):
        for failures, expected in ((0, True), (1, True), (2, True), (3, False)):
            item = evidence(failures)
            self.assertEqual(cs.passed(item), expected)
            self.assertEqual(st.passed(item), expected)
            self.assertEqual(cs.metrics(item)['passed_count'], 20-failures)
        item = evidence(2)
        item.update(passed_count=20, success_rate=1, maximum_consecutive_failures=0)
        item['attempts'][2]['sites']['YouTube']['status'] = 'failed'
        self.assertFalse(cs.passed(item))

    def test_explicit_site_or_android_certificate_failure_is_fatal_even_at_95_percent(self):
        for key in ('site', 'android'):
            item = evidence()
            if key == 'site':
                item['attempts'][0]['sites']['ChatGPTTrace'].update(status='failed', tls_error_kind='certificate_verification_failed')
            else:
                item['attempts'][0]['android_tls'].update(status='failed', error_type='certificate_verification_failed')
            self.assertEqual(cs.metrics(item)['success_rate'], .95)
            self.assertFalse(cs.passed(item))
        # Exit-IP changes remain allowed.
        item = evidence(); item['attempts'][5]['sites']['ChatGPTTrace']['exit_ip'] = '1.1.1.1'
        self.assertTrue(cs.passed(item))

    def test_missing_rounds_rushed_gaps_overlap_or_no_post_peer_sample_cannot_publish(self):
        for fault in ('missing', 'rushed', 'overlap', 'no_peer', 'late_peer', 'nan', 'bad_round', 'missing_site'):
            item = evidence()
            if fault == 'missing': item['attempts'].clear()
            elif fault == 'rushed': item['attempts'][1]['started_offset_seconds'] = 1
            elif fault == 'overlap': item['attempts'][0]['finished_offset_seconds'] = 31
            elif fault == 'no_peer': item['peer_completed_offset_seconds'] = None
            elif fault == 'late_peer': item['peer_completed_offset_seconds'] = 571
            elif fault == 'nan': item['attempts'][0]['finished_offset_seconds'] = float('nan')
            elif fault == 'bad_round': item['attempts'][0]['round'] = 2
            else: item['attempts'][0]['sites'].pop('Google')
            self.assertFalse(cs.passed(item), fault)

    def test_new_policy_accepts_actual_short_window_and_keeps_old_version_requirements(self):
        attempts = [sample(i, (i-1)*15) for i in range(1, 4)]
        current = cs.summarize(attempts, cutoff=20)
        self.assertTrue(st.passed(current))
        self.assertIsNone(cs.settings()['minimum_rounds'])
        self.assertEqual(cs.settings()['random_idle_seconds_range'], [3, 10])
        self.assertEqual(cs.settings(3)['minimum_start_interval_seconds'], 15)
        old = copy.deepcopy(current); old['version'] = 2
        self.assertFalse(st.passed(old))
        old = evidence(); old['version'] = 2
        self.assertTrue(st.passed(old))
        old['attempts'].pop()
        self.assertFalse(st.passed(old))
        self.assertEqual(st.settings([{'stability': {'version': 2}}])['minimum_start_interval_seconds'], 30)

    def test_random_policy_does_not_reinterpret_historical_fixed_interval(self):
        attempts = [sample(1, 0), sample(2, 5)]
        current = cs.summarize(attempts, cutoff=4)
        self.assertTrue(cs.passed(current))
        historical = copy.deepcopy(current); historical['version'] = 3
        self.assertFalse(cs.passed(historical))
        rushed = copy.deepcopy(current); rushed['attempts'][1]['started_offset_seconds'] = 3
        self.assertFalse(cs.passed(rushed))

    def test_successful_percentiles_ignore_failed_short_elapsed_and_do_not_pool_targets(self):
        item = evidence(1)
        item['attempts'][0]['sites']['Google']['elapsed_ms'] = 1
        for index, x in enumerate(item['attempts'][1:], 1):
            x['sites']['Google']['elapsed_ms'] = index*10
            x['sites']['YouTube']['elapsed_ms'] = 1000+index*10
        metrics = cs.core_metrics(item)
        self.assertEqual(metrics['Google']['sample_count'], 19)
        self.assertEqual(metrics['Google']['median_ms'], 100)
        self.assertEqual(metrics['Google']['p99_ms'], 190)
        self.assertEqual(metrics['YouTube']['p95_ms'], 1190)
        self.assertTrue(st.quality_passed(item, 1, 1, 1))  # continuous values rank, not hard-cap

    def test_rank_prefers_success_rate_then_streak_then_successful_p95(self):
        rows = [record('n-a'), record('n-b'), record('n-c')]
        for row in rows: row['stability'] = evidence()
        rows[1]['stability'] = evidence(1)
        for x in rows[0]['stability']['attempts']: x['sites']['YouTube']['elapsed_ms'] = 4000
        self.assertLess(a.rank_key(rows[0]), a.rank_key(rows[1]))
        self.assertLess(a.rank_key(rows[2]), a.rank_key(rows[0]))
        same_rate = evidence(2)
        alternating = evidence()
        for index in (0, 2): alternating['attempts'][index]['sites']['Google204']['status'] = 'failed'
        rows[0]['stability'] = same_rate; rows[1]['stability'] = alternating
        self.assertLess(a.rank_key(rows[1]), a.rank_key(rows[0]))


class ScheduleTests(unittest.TestCase):
    def run_schedule(self, peer_at=600, bad_control=False):
        class Clock:
            value = 0
            def now(self): return self.value
            def sleep(self, seconds): self.value += seconds
        class ImmediatePool:
            def __init__(self, max_workers): self.workers = max_workers
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def submit(self, fn, *args):
                job = futures.Future()
                try: job.set_result(fn(*args))
                except Exception as error: job.set_exception(error)
                return job
        clock = Clock(); controls = []; checkpoints = []
        def probe(id, number, origin):
            item = sample(number, clock.now()-origin)
            clock.value += 1
            return item
        def control(number, origin):
            controls.append(clock.now())
            if bad_control: raise RuntimeError('对照异常')
        def checkpoint(attempts, cutoff, complete):
            checkpoints.append(complete)
            return {id: cs.summarize(copy.deepcopy(x), cutoff) for id, x in attempts.items()}
        with patch.object(cs.futures, 'ThreadPoolExecutor', ImmediatePool):
            result = cs.schedule(['a', 'b', 'c'], probe, lambda: clock.now() >= peer_at,
                control, checkpoint, clock=clock.now, sleep=clock.sleep, workers=2)
        return result, controls, checkpoints

    def test_time_scheduler_continues_until_peer_then_checks_every_node(self):
        results, controls, checkpoints = self.run_schedule(peer_at=700)
        self.assertGreater(len(controls), 10)
        self.assertTrue(checkpoints[-1]); self.assertIn(False, checkpoints)
        for item in results.values():
            self.assertTrue(cs.passed(item)); self.assertGreater(item['round_count'], 20)
            self.assertGreaterEqual(item['attempts'][-1]['started_offset_seconds'], item['peer_completed_offset_seconds'])
            self.assertTrue(all(3 <= a['next_idle_seconds'] <= 10 for a in item['attempts'][:-1]))
            self.assertTrue(all(b['started_offset_seconds'] >= a['finished_offset_seconds'] + a['next_idle_seconds'] - .001
                for a,b in zip(item['attempts'], item['attempts'][1:])))
            self.assertTrue(all(b['started_offset_seconds']-a['finished_offset_seconds'] >= 2.999
                and b['started_offset_seconds'] >= a['finished_offset_seconds']
                for a,b in zip(item['attempts'], item['attempts'][1:])))

    def test_fast_peer_does_not_wait_for_twenty_rounds(self):
        results, _, _ = self.run_schedule(peer_at=0)
        self.assertTrue(all(len(x['attempts']) == 1 and cs.passed(x) for x in results.values()))

    def test_control_failure_aborts_and_empty_shard_is_safe_without_core_or_api(self):
        with self.assertRaisesRegex(RuntimeError, '对照异常'): self.run_schedule(bad_control=True)
        with tempfile.TemporaryDirectory() as folder, patch.object(cs.s, 'Core') as core, patch.object(cs, 'PeerJob') as peer:
            result = cs.observe([], {}, 'unused', folder)
            self.assertTrue(result['complete']); self.assertTrue(result['controls_valid'])
            core.assert_not_called(); peer.assert_not_called()

    def test_real_pool_limits_parallel_nodes_and_never_overlaps_one_node(self):
        active = set(); peaks = []; lock = threading.Lock()
        def probe(id, number, origin):
            with lock:
                self.assertNotIn(id, active); active.add(id); peaks.append(len(active))
            started = time.monotonic()-origin
            time.sleep(.01)
            item = sample(number, started); item['finished_offset_seconds'] = time.monotonic()-origin
            with lock: active.remove(id)
            return item
        with patch.object(cs.random, 'uniform', return_value=.03), patch.object(cs, 'PEER_POLL_SECONDS', .03):
            origin = time.monotonic()
            result = cs.schedule(['a','b','c','d'], probe, lambda: time.monotonic()-origin >= .04,
                lambda *_: None, lambda attempts, cutoff, complete: attempts, workers=2)
        self.assertEqual(max(peaks), 2); self.assertEqual(active, set())
        self.assertTrue(all(len(x) >= 2 for x in result.values()))
        for items in result.values():
            self.assertGreaterEqual(items[1]['started_offset_seconds'], items[0]['finished_offset_seconds'])

    def test_peer_queries_current_attempt_and_aborts_on_upstream_failure(self):
        env = {'GITHUB_REPOSITORY': 'owner/repo', 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2', 'GH_TOKEN': 'private'}
        with patch.dict(cs.os.environ, env), patch.object(cs.s.requests, 'get') as get:
            peer = cs.PeerJob()
            get.return_value.json.return_value = {'jobs': [{'name': cs.PEER_JOB, 'status': 'in_progress', 'conclusion': None}]}
            self.assertFalse(peer())
            self.assertIn('/runs/123/attempts/2/jobs', get.call_args.args[0])
            get.return_value.json.return_value['jobs'][0].update(status='completed', conclusion='success')
            self.assertTrue(peer())
            get.return_value.json.return_value['jobs'][0]['conclusion'] = 'failure'
            with self.assertRaisesRegex(RuntimeError, '主筛选任务失败'): peer()


class MergeTests(unittest.TestCase):
    def test_observer_requires_exact_batch_cohort_complete_raw_controls(self):
        row = record('n-a'); row['upload_precheck'] = verified_upload_precheck()
        bundle = {'id': 'batch', 'nodes': [{'name': 'n-a', 'server': '8.8.8.8', 'port': 443}, {'name': 'n-b', 'server': '1.1.1.1', 'port': 443}]}
        skipped = record('n-b'); skipped['entry']['status'] = 'failed'
        part = observation(bundle, [row])
        cs.merge(bundle, [part], [row, skipped], 1, a.shard_nodes)
        self.assertTrue(st.passed(row['stability'])); self.assertNotIn('stability', skipped)
        for fault in ('batch', 'missing', 'duplicate', 'controls', 'control_window', 'rounds', 'complete', 'cohort'):
            bad = copy.deepcopy(part)
            if fault == 'batch': bad['bundle_id'] = 'old'
            elif fault == 'missing': bad['diagnostic']['nodes'] = []
            elif fault == 'duplicate': bad['diagnostic']['nodes'] *= 2
            elif fault == 'controls': bad['diagnostic']['controls'][0]['android_tls']['chain_verified'] = False
            elif fault == 'control_window': bad['diagnostic']['controls'] = bad['diagnostic']['controls'][:1]
            elif fault == 'rounds': bad['diagnostic']['nodes'][0]['stability']['attempts'].clear()
            elif fault == 'complete': bad['diagnostic']['complete'] = False
            else: bad['diagnostic']['nodes'][0]['id'] = 'n-b'
            with self.assertRaises(ValueError, msg=fault): cs.merge(bundle, [bad], [row, skipped], 1, a.shard_nodes)
        # cached success cannot override a raw failing node
        bad = copy.deepcopy(part); bad['diagnostic']['nodes'][0]['stability'] = evidence(3)
        bad['diagnostic']['nodes'][0]['stability']['status'] = 'passed'
        cs.merge(bundle, [bad], [row, skipped], 1, a.shard_nodes)
        self.assertFalse(st.passed(row['stability']))

    def test_uplink_cannot_replace_original_measurements_or_cross_batches(self):
        row = record('n-a'); row['upload_precheck'] = upload_evidence()['precheck']
        measured = copy.deepcopy(row); measured.update(upload=upload_evidence(), post_upload_tls=verified_tls())
        diagnostic = {'node_count': 1, 'controls_valid': True, 'nodes': [{'id': 'n-a', 'upload': measured['upload'], 'post_upload_tls': measured['post_upload_tls']}],
            'controls': {'before': upload_evidence(), 'after': upload_evidence()},
            'core_health': {'process_alive': True, 'api_available': True}}
        stage = {'bundle_id': 'batch', 'records': [measured], 'diagnostic': diagnostic}
        for fault in ('batch', 'web', 'missing', 'precheck', 'control'):
            bad = copy.deepcopy(stage)
            if fault == 'batch': bad['bundle_id'] = 'old'
            elif fault == 'web': bad['records'][0]['download']['speed_mib_s'] = 99999
            elif fault == 'missing': bad['diagnostic']['nodes'] = []
            elif fault == 'control': bad['diagnostic']['controls']['after']['attempts'].pop()
            else:
                bad['records'][0]['upload']['precheck']['uploaded_bytes'] = 1
                bad['diagnostic']['nodes'][0]['upload']['precheck']['uploaded_bytes'] = 1
            with self.assertRaises(ValueError, msg=fault): a.merge_uplink({'id': 'batch'}, [copy.deepcopy(row)], bad, {'n-a': {}})
        original = copy.deepcopy(row)
        a.merge_uplink({'id': 'batch'}, [original], stage, {'n-a': {}})
        self.assertTrue(a.upload_speed.passed(original['upload']))

    def test_report_shows_variable_rounds_success_rate_and_p95_instead_of_five_round_claim(self):
        report, config = fixture(); report['nodes'][0]['stability'] = evidence(2)
        report['stability_policy'] = cs.settings(); report['publication_mode'] = 'full'
        text = render(report, config)
        self.assertIn('18/20 / 90.0%', text); self.assertIn('P95 / P99', text)
        self.assertIn('每轮结束后随机等待3～10秒', text); self.assertIn('不设固定轮数', text); self.assertNotIn('| 五轮间隔稳定性 |', text)
        self.assertIn('JSON', text)


class PipelineTests(unittest.TestCase):
    def test_preflight_and_continuation_measure_each_early_stage_exactly_once(self):
        node = {'name': 'n-a', 'type': 'ss', 'server': '8.8.8.8', 'port': 443}
        pre = a.summarize_rounds([{'Google204': {'status': 'passed', 'elapsed_ms': 100}}]*3, ('Google204',))['Google204']
        controls = {}
        with patch.object(a.s, 'Core'), patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1234})), \
             patch.object(a.s, 'query_exit', return_value=None), patch.object(a.app_tls, 'check', return_value=verified_tls()):
            early = Mock(side_effect=lambda p: verified_upload_precheck())
            websites = Mock(return_value={k: {'status': 'passed', 'elapsed_ms': 100} for k in a.POST_SITES})
            precheck = Mock(return_value=pre); tcp = Mock(return_value={'status': 'passed'})
            first, count = a.probe_pipeline([node], 'unused', Path('.'), precheck=precheck,
                probe=tcp, upload_precheck=early, upload_controls=controls, site_check=websites, preflight_only=True)
            websites.assert_not_called(); self.assertEqual(precheck.call_count, 1); self.assertEqual(tcp.call_count, 1)
            self.assertEqual(early.call_count, 3)  # candidate + before/after direct controls
            part = {'bundle_id': 'batch', 'index': 0, 'count': 1, 'endpoint_count': count,
                    'records': first, 'upload_precheck_controls': controls}
            bundle = {'id': 'batch', 'nodes': [node], 'early_upload_precheck': True, 'parallel_observation': True}
            a.merge_shards(bundle, [part], 1, preflight_only=True)
            original = copy.deepcopy(first)
            second, count2 = a.probe_pipeline([node], 'unused', Path('.'), precheck=precheck,
                probe=tcp, upload_precheck=early, upload_controls=controls, site_check=websites,
                initial_records=first, download=lambda p: {'status': 'failed'})
            self.assertEqual(count, count2); self.assertEqual(websites.call_count, 3)
            self.assertEqual(early.call_count, 3); self.assertEqual(precheck.call_count, 1); self.assertEqual(tcp.call_count, 1)
            self.assertEqual(first, original)
            part['records'] = second
            a.merge_shards(bundle, [part], 1)
            part['records'][0]['port'] = 444
            with self.assertRaisesRegex(ValueError, '定义不一致'): a.merge_shards(bundle, [part], 1)

    def test_parallel_final_publication_joins_raw_evidence_without_repeat_tests(self):
        row = record('n-a'); row.update(server='8.8.8.8', port=443, protocol='ss', upload_precheck=upload_evidence()['precheck'])
        node = {'name': 'n-a', 'type': 'ss', 'server': '8.8.8.8', 'port': 443}
        bundle = {'nodes': [node], 'base': {}, 'metadata': {}, 'sources': [], 'input_count': 1,
                  'rejected': [], 'services': {}, 'scope': 'all_subscriptions', 'id': 'batch', 'parallel_observation': True}
        with tempfile.TemporaryDirectory() as folder:
            cwd = os.getcwd()
            try:
                os.chdir(folder); root = Path('.node-work/availability'); root.mkdir(parents=True)
                (root / 'bundle.json').write_text(json.dumps(bundle))
                def upload(rows, *args, **kwargs):
                    self.assertTrue(kwargs['reuse_precheck'])
                    rows[0].update(upload=upload_evidence(), post_upload_tls=verified_tls())
                    return {'updated_at': '2026-10-12T08:00:00+08:00', 'node_count': 1, 'controls_valid': True,
                        'nodes': [{'id': 'n-a', 'upload': rows[0]['upload'], 'post_upload_tls': rows[0]['post_upload_tls']}],
                        'controls': {'before': upload_evidence(), 'after': upload_evidence()},
                        'core_health': {'process_alive': True, 'api_available': True}}
                with patch.object(sys, 'argv', ['availability', '--phase', 'uplink-stage', '--mihomo', 'unused', '--shard-count', '1']), \
                     patch.object(a, 'merge_shards', return_value=([copy.deepcopy(row)], 1)), \
                     patch.object(a.upload_speed, 'recheck', side_effect=upload) as up:
                    a.main(); up.assert_called_once()
                self.assertTrue((root / 'uplink-stage.json').exists())
                self.assertFalse(Path('优选配置.yaml').exists())
                obs = Path('.node-work/observations'); obs.mkdir(parents=True)
                part = observation(bundle, [row]); part['diagnostic']['nodes'][0]['stability'] = evidence(2)
                (obs / 'observation-0.json').write_text(json.dumps(part))
                with patch.object(sys, 'argv', ['availability', '--phase', 'publish', '--mihomo', 'unused', '--shard-count', '1', '--uplink-result', str(root / 'uplink-stage.json')]), \
                     patch.object(a, 'merge_shards', return_value=([copy.deepcopy(row)], 1)), \
                     patch.object(a.s, 'lookup_ip_types', return_value={}), patch.object(a.ip_reputation, 'lookup', return_value={}), \
                     patch.object(a.upload_speed, 'recheck') as up, patch.object(a.stability, 'recheck') as old, \
                     patch.object(a.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    a.main(); up.assert_not_called(); old.assert_not_called()
                result = json.loads(Path('连通性报告.json').read_text())
                self.assertEqual(result['published_node_count'], 1)
                self.assertEqual(result['stability_policy']['minimum_success_rate'], .9)
                self.assertEqual(result['nodes'][0]['stability']['passed_count'], 18)
                self.assertEqual(result['stability_recheck']['scope'], 'domestic_TCP_and_3MB_upload_passed')
                self.assertIn('18/20 / 90.0%', Path('README.md').read_text())
            finally: os.chdir(cwd)


if __name__ == '__main__': unittest.main()
