import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a
from attempt_report import write_attempt


class RequiredSiteTests(unittest.TestCase):
    def record(self):
        return {'id': 'n-a', 'entry': {'status': 'passed'},
            'precheck': {'status': 'passed', 'round_count': 3, 'passed_count': 3},
            'download': {'status': 'passed', 'speed_mib_s': 5},
            'exit': {'country_code': 'TW', 'exit_ip': '8.8.8.8'},
            'websites': {label: {'status': 'passed', 'round_count': 3, 'passed_count': 3,
                'median_elapsed_ms': 100, 'p95_elapsed_ms': 120, 'jitter_ms': 20}
                for label in a.OVERSEAS_SITES}}

    def test_each_required_site_is_mandatory_for_both_pools(self):
        good = self.record()
        self.assertTrue(a.web_quality_eligible(good))
        self.assertTrue(a.regional_eligible(good))
        self.assertEqual(set(a.REQUIRED_SITES), {'Google', 'YouTube', 'ChatGPT', 'Claude', 'Gemini',
            'GitHub', 'Wikipedia', 'Reddit', 'X', 'Instagram', 'Telegram', 'Discord', 'Facebook'})
        for label in a.REQUIRED_SITES:
            for condition in ('missing', 'unstable', 'needs_review', 'single_round'):
                bad = copy.deepcopy(good)
                if condition == 'missing': bad['websites'].pop(label)
                elif condition == 'single_round': bad['websites'][label].update(round_count=1, passed_count=1)
                else: bad['websites'][label].update(status=condition, passed_count=2)
                self.assertFalse(a.web_quality_eligible(bad), (label, condition))
                self.assertFalse(a.regional_eligible(bad), (label, condition))

    def test_trace_success_cannot_trigger_download_when_claude_page_is_blocked(self):
        pages = {label: {'status': 'passed', 'elapsed_ms': 100} for label in a.POST_SITES}
        pages['Claude'] = {'status': 'needs_review', 'http_status': 403, 'elapsed_ms': 100}
        node = {'name': 'n-a', 'type': 'ss', 'server': '8.8.8.8', 'port': 443}
        pre = a.summarize_rounds([{'Google204': {'status': 'passed', 'elapsed_ms': 10}}] * 3,
            ('Google204',))['Google204']
        with patch.object(a.s, 'Core'), patch.object(a.s, 'query_exit', return_value=None), \
             patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1234})):
            rows, _ = a.probe_pipeline([node], 'unused', Path('.'), precheck=lambda port: pre,
                probe=lambda key, pace: {'status': 'passed'}, site_check=lambda port: pages,
                download=lambda port: self.fail('blocked required page must stop downloads'),
                large_download=lambda port: self.fail('blocked required page must stop large downloads'))
        self.assertEqual(rows[0]['download']['status'], 'skipped')
        self.assertEqual(rows[0]['websites']['ClaudeTrace']['status'], 'passed')
        bundle = {'id': 'batch', 'nodes': [node]}
        part = {'bundle_id': 'batch', 'index': 0, 'count': 1, 'endpoint_count': 1, 'records': rows}
        a.merge_shards(bundle, [part], 1)
        rows[0]['download'] = {'status': 'passed', 'received_bytes': a.DOWNLOAD_BYTES, 'elapsed_ms': 1000}
        with self.assertRaises(ValueError):
            a.merge_shards(bundle, [part], 1)

    def test_zero_qualified_full_run_keeps_complete_audit_and_does_not_claim_publication(self):
        record = self.record(); record['websites']['Claude'].update(status='needs_review', passed_count=0,
            attempts=[{'status': 'needs_review', 'http_status': 403, 'reason': 'challenge'}] * 3)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_attempt(root, [record], {'proxies': []}, a.REQUIRED_SITES, [], 2, '2026-10-10')
            report = json.loads((root / 'full-test-report.json').read_text())
            self.assertEqual(report['nodes'], [record])
            self.assertEqual(report['selected_node_count'], 0)
            self.assertEqual(report['selection_outcome'], 'no_eligible_nodes_previous_subscription_retained')
            self.assertEqual(report['website_counts']['Claude']['attempt_http_status_counts'], {'403': 3})
            self.assertIn('不代表通过这次13站', (root / 'full-test-report.md').read_text())
