"""A later TLS rejection must not retroactively invalidate an earlier stage."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import concurrent.futures as futures
import tempfile
import json

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a
import quality_policy as qp
from tls_fixture import verified_tls
from upload_fixture import verified_upload_precheck
from medium_speed_fixture import verified_medium
from high_speed_fixture import verified_high
import upload_speed as up
import stability
from test_upload_speed import sample as uploaded, evidence as upload_evidence


class StageOrderTests(unittest.TestCase):
    def test_later_tls_error_is_rejection_not_invalid_earlier_stage(self):
        node = {'name': 'n-a', 'type': 'http', 'server': '8.8.8.8', 'port': 80}
        pre = a.summarize_rounds([{'Google204': {'status': 'passed', 'elapsed_ms': 100}}]*3, ('Google204',))['Google204']
        controls = {}
        with patch.object(a.s, 'Core'), patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1234})), \
                patch.object(a.s, 'query_exit', return_value=None), \
                patch.object(a.app_tls, 'check', return_value=verified_tls()), \
                patch.object(a.application_quality, 'check', return_value={
                    'status': 'diagnostic_only', 'youtube_page': {'status': 'failed',
                        'error_type': 'SSLError', 'tls_error_kind': 'certificate_verification_failed'}}):
            records, endpoints = a.probe_pipeline([node], 'unused', Path('.'),
                precheck=lambda _: pre, probe=lambda *_: {'status': 'passed'},
                upload_precheck=verified_upload_precheck, upload_controls=controls,
                site_check=lambda _: {k: {'status': 'passed', 'elapsed_ms': 100} for k in a.DAILY_POST_SITES},
                download=lambda _: {'status': 'passed', 'received_bytes': a.DOWNLOAD_BYTES, 'elapsed_ms': 100},
                medium_download=lambda _: verified_medium(),
                large_download=lambda _: verified_high(), policy_version=qp.VERSION)
        bundle = {'id': 'batch', 'nodes': [node], 'selection_policy_version': qp.VERSION,
                  'early_upload_precheck': True}
        part = {'bundle_id': 'batch', 'index': 0, 'count': 1, 'records': records,
                'endpoint_count': endpoints, 'upload_precheck_controls': controls}
        merged, _ = a.merge_shards(bundle, [part], 1)
        self.assertFalse(a.web_quality_eligible(merged[0]))
        self.assertEqual(merged[0]['app_tls']['status'], 'passed')

    def test_prefix_gate_ignores_only_later_errors_and_keeps_early_tls_rejection(self):
        from test_stability_first import row
        record = row()
        record['upload_precheck'] = verified_upload_precheck()
        error = {'status': 'failed', 'tls_error_kind': 'certificate_verification_failed'}
        for stage in ('download', 'medium_speed_download', 'high_speed_download', 'application_quality', 'post_upload_tls'):
            record[stage] = error
            self.assertFalse(a.pre_application_tls_failure(record), stage)
            self.assertTrue(a.destination_tls_failure(record), stage)
            record.pop(stage)
        record['upload_precheck'] = error
        self.assertTrue(a.pre_application_tls_failure(record))
        record['upload_precheck'] = verified_upload_precheck()
        record['websites']['Google']['attempts'][0] = error
        self.assertTrue(a.pre_application_tls_failure(record))


class ScheduledUploadTests(unittest.TestCase):
    def test_interrupted_recheck_saves_only_fresh_partial_results(self):
        records = [{'id': 'n-' + str(i), 'selection_policy_version': qp.VERSION,
                    'upload_precheck': verified_upload_precheck(),
                    'upload': {'status': 'passed', 'old': True}, 'post_upload_tls': verified_tls()} for i in range(2)]
        def interrupted(rows, ports, root, reuse, checkpoint):
            self.assertTrue(all('upload' not in r for r in rows))
            rows[0].update(upload={'status': 'failed'}, post_upload_tls=verified_tls())
            checkpoint()
            raise RuntimeError('fixture interruption')
        with tempfile.TemporaryDirectory() as folder, patch.object(up.s, 'Core'), \
                patch.object(up.s, 'make_listeners', return_value=([], {'n-0': 1000, 'n-1': 1001})), \
                patch.object(up, 'check', return_value=upload_evidence()), \
                patch.object(up, 'observe_scheduled', side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError, 'fixture interruption'):
                up.recheck(records, {r['id']: {} for r in records}, 'unused', folder, reuse_precheck=True)
            partial = json.loads((Path(folder) / 'upload-results.json').read_text())
        self.assertFalse(partial['complete']); self.assertFalse(partial['controls_valid'])
        self.assertEqual(partial['measured_node_count'], 1)
        self.assertEqual([r['id'] for r in partial['nodes']], ['n-0'])

    def test_repeat_gap_does_not_block_other_nodes_and_is_still_at_least_twenty_seconds(self):
        class Clock:
            value = 0
            def now(self): return self.value
            def sleep(self, seconds): self.value += seconds
        class ImmediatePool:
            def __init__(self, max_workers): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def submit(self, fn, *args):
                future = futures.Future()
                try: future.set_result(fn(*args))
                except Exception as error: future.set_exception(error)
                return future
        clock, events, rounds = Clock(), [], {}
        records = [{'id': 'n-' + str(i), 'selection_policy_version': qp.VERSION,
                    'upload_precheck': verified_upload_precheck()} for i in range(3)]
        ports = {r['id']: 1000+i for i, r in enumerate(records)}
        def loaded(port, directory):
            rounds[port] = rounds.get(port, 0) + 1
            events.append((port, rounds[port], clock.value))
            return uploaded()
        real_check = up.check
        def control_or_node(port, *args, **kwargs):
            return upload_evidence() if port is None else real_check(port, *args, **kwargs)
        with tempfile.TemporaryDirectory() as folder, patch.object(up.s, 'Core'), \
                patch.object(up.s, 'make_listeners', return_value=([], ports)), \
                patch.object(up, 'WORKERS', 1), patch.object(up, 'check', side_effect=control_or_node), \
                patch.object(up, 'loaded_sample', side_effect=loaded), \
                patch.object(up.app_tls, 'check', return_value=verified_tls()), \
                patch.object(up.futures, 'ThreadPoolExecutor', ImmediatePool), \
                patch.object(up.time, 'monotonic', side_effect=clock.now), \
                patch.object(up.time, 'sleep', side_effect=clock.sleep), \
                patch.object(stability, 'core_health', return_value={'process_alive': True, 'api_available': True}):
            result = up.recheck(records, {r['id']: {} for r in records}, 'unused', folder, reuse_precheck=True)
        self.assertTrue(result['controls_valid'])
        self.assertEqual([x[1] for x in events], [1, 1, 1, 2, 2, 2])
        self.assertEqual([x[2] for x in events[:3]], [0, 0, 0])
        self.assertTrue(all(x[2] >= 20 for x in events[3:]))
        self.assertEqual(clock.value, 20)
        self.assertTrue(all(qp.upload_observed(r) for r in records))
