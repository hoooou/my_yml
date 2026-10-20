import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a
import publish_subscription as pub
from test_medium_speed import record
from test_continuous_stability import evidence


class RecoveredEvidenceTests(unittest.TestCase):
    def fixture(self):
        row = record('n-a'); row.update(server='8.8.8.8', port=443, protocol='ss', stability=evidence())
        cached = copy.deepcopy(row); cached.update(ip_type={'status': 'success', 'hosting': False},
            ip_reputation={'status': 'success', 'network_purity_score': 99.2})
        bundle = {'input_count': 1}
        report = {'input_unique_count': 1, 'parseable_count': 1, 'nodes': [cached],
            'updated_at': '2026-10-12T07:47:39+08:00'}
        return bundle, [row], report

    def test_restore_metadata_and_time_without_replacing_probe_evidence(self):
        bundle, records, report = self.fixture()
        old_attempts = copy.deepcopy(records[0]['stability']['attempts'])
        result = a.reuse_measurements(bundle, records, report, '123')
        self.assertFalse(result['new_probes'])
        self.assertEqual(bundle['measurements_updated_at'], report['updated_at'])
        self.assertEqual(records[0]['ip_reputation']['network_purity_score'], 99.2)
        self.assertEqual(records[0]['stability']['attempts'], old_attempts)

    def test_mismatched_node_batch_raw_tls_web_or_stability_never_reuses_metadata(self):
        for fault in ('batch', 'duplicate', 'web', 'tls', 'stable'):
            bundle, records, report = self.fixture()
            original = copy.deepcopy(records)
            if fault == 'batch': report['input_unique_count'] = 2
            elif fault == 'duplicate': report['nodes'] *= 2
            elif fault == 'web': report['nodes'][0]['websites']['Google']['median_elapsed_ms'] = 1
            elif fault == 'tls': report['nodes'][0]['app_tls']['targets']['chatgpt.com']['attempts'][0]['hostname_verified'] = False
            else: report['nodes'][0]['stability']['attempts'][0]['sites']['Google204']['status'] = 'failed'
            with self.assertRaises(ValueError, msg=fault): a.reuse_measurements(bundle, records, report, '123')
            self.assertEqual(records, original)

    def test_global_manual_defaults_to_recommended_and_other_groups_auto_select(self):
        row = record('n-a')
        config = a.render_comparison({}, [row], {'n-a': {'name': 'n-a', 'type': 'http', 'server': '8.8.8.8', 'port': 443}})
        self.assertEqual(len(config['proxy-groups']), 6)
        for group in config['proxy-groups']:
            self.assertEqual(group['type'], 'select' if group['name'] == '🚀 全局选择' else 'url-test')
            if group['name'] == '🚀 全局选择':
                self.assertEqual(group['default-selected'], '⭐ 综合优选')
                self.assertEqual(group['proxies'][0], '⭐ 综合优选')
            else:
                self.assertEqual(group['tolerance'], 50)
            self.assertEqual(group['url'], 'https://claude.ai/cdn-cgi/trace')
            self.assertEqual(group['interval'], 300)
            self.assertEqual(group['timeout'], 5000)
            self.assertEqual(group['expected-status'], 200)
            self.assertFalse(group['lazy'])
        self.assertTrue(any(row['name'] in group['proxies'] for group in config['proxy-groups']))


class PublicationGitTests(unittest.TestCase):
    def test_report_compaction_preserves_every_observation(self):
        data = {'nodes': [{'name': '台湾', 'attempts': [{'status': 'passed', 'elapsed_ms': 42}]}]}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / '连通性报告.json'
            path.write_text(json.dumps(data, ensure_ascii=False, indent=12))
            before = path.stat().st_size
            with patch.object(pub, 'REPORT_COMPACT_THRESHOLD', 1):
                pub.compact_report(path)
            self.assertEqual(json.loads(path.read_text()), data)
            self.assertLess(path.stat().st_size, before)

    def test_large_file_and_hook_rejections_are_not_branch_races(self):
        self.assertFalse(pub.retryable_push('remote: error: GH001: Large files detected.\n'
            '! [remote rejected] HEAD -> main (pre-receive hook declined)'))
        self.assertFalse(pub.retryable_push('! [remote rejected] HEAD -> main (protected branch hook declined)'))
        self.assertTrue(pub.retryable_push('! [rejected] HEAD -> main (fetch first)'))
        self.assertTrue(pub.retryable_push('! [rejected] HEAD -> main (non-fast-forward)'))

    def test_same_verified_source_rebuild_can_publish_despite_validation_timestamp_drift(self):
        candidate = {'updated_at': '2026-10-12T19:22:00+08:00', 'configuration_validation': 'passed',
                     'measurement_recovery': {'source_run': '123', 'new_probes': False}}
        remote = {'updated_at': '2026-10-12T19:20:40+08:00', 'source_run': '123'}
        self.assertTrue(pub.validated_same_run_rebuild(candidate, remote))
        for change in ({'source_run': '456'}, {'measurement_recovery': {'source_run': '456'}},
                       {'updated_at': '2026-10-12T19:23:00+08:00'}):
            self.assertFalse(pub.validated_same_run_rebuild(candidate, {**remote, **change}))
        self.assertFalse(pub.validated_same_run_rebuild({**candidate, 'configuration_validation': 'failed'}, remote))
        self.assertFalse(pub.validated_same_run_rebuild({**candidate, 'measurement_recovery': {'source_run': '123', 'new_probes': True}}, remote))
        self.assertFalse(pub.validated_same_run_rebuild(candidate, {'updated_at': remote['updated_at']}))

    def test_old_report_from_checkout_is_never_republished_as_current_run(self):
        with tempfile.TemporaryDirectory() as folder:
            cwd = os.getcwd()
            try:
                os.chdir(folder)
                Path('最新检测.json').write_text(json.dumps({'source_run': '123'}))
                with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_RUN_ID': '456'}), \
                        patch.object(sys, 'argv', ['publish_subscription']), patch.object(pub, 'publish') as publish:
                    pub.main()
                publish.assert_not_called()
            finally:
                os.chdir(cwd)

    def test_zero_candidate_still_publishes_latest_detection_without_subscription(self):
        with tempfile.TemporaryDirectory() as folder:
            cwd = os.getcwd()
            try:
                os.chdir(folder)
                Path('最新检测.json').write_text(json.dumps({'updated_at': '2026-10-12T15:21:01+08:00',
                    'source_run': 'fixture-run', 'selected_node_count': 0,
                    'selection_outcome': 'no_eligible_nodes_previous_subscription_retained'}))
                Path('README.md').write_text('最新全量检测：0个候选，保留旧订阅')
                with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_RUN_ID': 'fixture-run'}), \
                        patch.object(sys, 'argv', ['publish_subscription']), patch.object(pub, 'publish') as publish:
                    pub.main()
                publish.assert_called_once()
                self.assertNotIn('优选配置.yaml', publish.call_args.kwargs['files'])
                self.assertNotIn('连通性报告.json', publish.call_args.kwargs['files'])
            finally:
                os.chdir(cwd)

    def command(self, root, *args):
        result = subprocess.run(['git', *args], cwd=root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def write_outputs(self, root, time, label):
        for name in pub.FILES:
            text = json.dumps({'updated_at': time, 'measurements_updated_at': time, 'label': label}) if name.endswith('.json') else label
            if name == 'README.md':
                text = f'# Manual documentation: {label}\n\n' + pub.replace_fragment('', label)
            (root/name).write_text(text)

    def test_stale_checkout_publishes_on_current_main_and_preserves_code_updates(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); remote = root/'remote'; remote.mkdir()
            self.command(remote, 'init', '--bare', '--initial-branch=main')
            old = root/'old'; other = root/'other'
            self.command(root, 'clone', str(remote), str(old))
            self.command(old, 'config', 'user.name', 'test'); self.command(old, 'config', 'user.email', 'test@example.invalid')
            self.write_outputs(old, '2026-10-12T06:00:00+08:00', 'initial')
            (old/'code.txt').write_text('initial')
            self.command(old, 'add', '.'); self.command(old, 'commit', '-m', 'initial'); self.command(old, 'push', 'origin', 'main')
            self.command(root, 'clone', str(remote), str(other))
            self.command(other, 'config', 'user.name', 'test'); self.command(other, 'config', 'user.email', 'test@example.invalid')
            self.write_outputs(other, '2026-10-12T07:00:00+08:00', 'earlier-pipeline')
            (other/'code.txt').write_text('new code')
            self.command(other, 'add', '.'); self.command(other, 'commit', '-m', 'upstream update'); self.command(other, 'push', 'origin', 'main')
            upstream = self.command(other, 'rev-parse', 'HEAD')
            self.write_outputs(old, '2026-10-12T08:00:00+08:00', 'latest-candidate')
            self.assertTrue(pub.publish(old))
            self.assertEqual(self.command(old, 'rev-parse', 'HEAD^'), upstream)
            self.assertEqual((old/'code.txt').read_text(), 'new code')
            self.assertEqual((old/'优选配置.yaml').read_text(), 'latest-candidate')
            self.assertEqual((old/'v2rayN.txt').read_text(), 'latest-candidate')
            self.assertIn('Manual documentation: earlier-pipeline', (old/'README.md').read_text())
            self.assertEqual(pub.readme_fragment((old/'README.md').read_text()), 'latest-candidate')
            self.assertEqual(self.command(old, 'log', '-1', '--format=%an'), 'github-actions[bot]')
            # Report refresh must not overwrite the current subscription YAML.
            self.write_outputs(old, '2026-10-12T09:00:00+08:00', 'report-refresh')
            self.assertTrue(pub.publish(old, files=tuple(name for name in pub.FILES
                if name not in ('优选配置.yaml', 'v2rayN.txt'))))
            self.assertEqual((old/'优选配置.yaml').read_text(), 'latest-candidate')
            self.assertEqual((old/'v2rayN.txt').read_text(), 'latest-candidate')
            # Zero-candidate reports update independently of the published measurements.
            saved_measurements = (old/'连通性报告.json').read_bytes()
            self.write_outputs(old, '2026-10-12T09:05:00+08:00', 'zero-candidate')
            self.assertTrue(pub.publish(old, files=pub.REPORT_FILES))
            self.assertEqual((old/'优选配置.yaml').read_text(), 'latest-candidate')
            self.assertEqual((old/'连通性报告.json').read_bytes(), saved_measurements)
            self.assertEqual((old/'v2rayN.txt').read_text(), 'latest-candidate')
            self.assertEqual(json.loads((old/'最新检测.json').read_text())['label'], 'zero-candidate')
            # Recovering older observations must not overwrite a newer subscription.
            self.write_outputs(old, '2026-10-12T07:30:00+08:00', 'older-candidate')
            self.assertFalse(pub.publish(old))
            self.assertEqual((old/'优选配置.yaml').read_text(), 'latest-candidate')
            self.assertEqual((old/'v2rayN.txt').read_text(), 'latest-candidate')
            # A same-source policy rebuild uses the original artifact timestamp,
            # which can precede the post-validation timestamp of its publication.
            self.write_outputs(old, '2026-10-12T09:10:00+08:00', 'validated-full')
            latest = json.loads((old/'最新检测.json').read_text()); latest['source_run'] = '123'
            (old/'最新检测.json').write_text(json.dumps(latest))
            self.assertTrue(pub.publish(old))
            self.write_outputs(old, '2026-10-12T09:09:55+08:00', 'same-run-groups')
            latest = json.loads((old/'最新检测.json').read_text())
            latest.update(updated_at='2026-10-12T09:11:00+08:00', configuration_validation='passed',
                          measurement_recovery={'source_run': '123', 'new_probes': False})
            (old/'最新检测.json').write_text(json.dumps(latest))
            self.assertTrue(pub.publish(old))
            self.assertEqual((old/'优选配置.yaml').read_text(), 'same-run-groups')

    def test_entry_point_refuses_shared_local_checkout(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}):
            with self.assertRaisesRegex(RuntimeError, '临时工作目录'): pub.main()
