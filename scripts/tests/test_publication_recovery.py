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

    def test_every_group_measures_delay_without_automatic_selection(self):
        row = record('n-a')
        config = a.render_comparison({}, [row], {'n-a': {'name': 'n-a', 'type': 'http', 'server': '8.8.8.8', 'port': 443}})
        self.assertEqual(len(config['proxy-groups']), 6)
        for group in config['proxy-groups']:
            self.assertEqual(group['type'], 'select')
            self.assertEqual(group['url'], 'https://connectivitycheck.gstatic.com/generate_204')
            self.assertEqual(group['interval'], 300)
            self.assertEqual(group['timeout'], 5000)
            self.assertEqual(group['expected-status'], 204)
            self.assertFalse(group['lazy'])
        self.assertTrue(any(row['name'] in group['proxies'] for group in config['proxy-groups']))


class PublicationGitTests(unittest.TestCase):
    def command(self, root, *args):
        result = subprocess.run(['git', *args], cwd=root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def write_outputs(self, root, time, label):
        for name in pub.FILES:
            (root/name).write_text(json.dumps({'updated_at': time, 'measurements_updated_at': time, 'label': label}) if name.endswith('.json') else label)

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
            self.assertEqual(self.command(old, 'log', '-1', '--format=%an'), 'github-actions[bot]')
            # Recovering older observations must not overwrite a newer subscription.
            self.write_outputs(old, '2026-10-12T07:30:00+08:00', 'older-candidate')
            self.assertFalse(pub.publish(old))
            self.assertEqual((old/'优选配置.yaml').read_text(), 'latest-candidate')

    def test_entry_point_refuses_shared_local_checkout(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}):
            with self.assertRaisesRegex(RuntimeError, '临时工作目录'): pub.main()
