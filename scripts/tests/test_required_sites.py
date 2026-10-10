import copy
import json
import os
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
            'websites': {**{label: {'status': 'passed', 'round_count': 3, 'passed_count': 3,
                'median_elapsed_ms': 100, 'p95_elapsed_ms': 120, 'jitter_ms': 20}
                for label in a.OVERSEAS_SITES},
                'ClaudeTrace': {'status': 'passed', 'round_count': 1, 'passed_count': 1}}}

    def test_each_required_site_is_mandatory_for_both_pools(self):
        good = self.record()
        self.assertTrue(a.web_quality_eligible(good))
        self.assertTrue(a.regional_eligible(good))
        self.assertEqual(set(a.REQUIRED_SITES), {'Google', 'YouTube', 'ChatGPT', 'Gemini',
            'GitHub', 'Wikipedia', 'Reddit', 'X', 'Instagram', 'Telegram', 'Discord', 'Facebook'})
        for label in a.REQUIRED_SITES:
            for condition in ('missing', 'unstable', 'needs_review', 'single_round'):
                bad = copy.deepcopy(good)
                if condition == 'missing': bad['websites'].pop(label)
                elif condition == 'single_round': bad['websites'][label].update(round_count=1, passed_count=1)
                else: bad['websites'][label].update(status=condition, passed_count=2)
                self.assertFalse(a.web_quality_eligible(bad), (label, condition))
                self.assertFalse(a.regional_eligible(bad), (label, condition))

    def test_claude_trace_is_mandatory_for_both_pools_and_homepage_is_ignored(self):
        good = self.record()
        good['websites']['Claude'] = {'status': 'needs_review', 'round_count': 3, 'passed_count': 0}
        self.assertTrue(a.web_quality_eligible(good))
        self.assertTrue(a.regional_eligible(good))
        self.assertNotIn('Claude', a.POST_SITES)
        self.assertNotIn('Claude', a.OVERSEAS_SITES)
        self.assertEqual(a.REQUIRED_TRACES, ('ClaudeTrace',))
        for condition in ('missing', 'failed', 'needs_review', 'unknown', 'invalid_rounds'):
            bad = copy.deepcopy(good)
            if condition == 'missing': bad['websites'].pop('ClaudeTrace')
            elif condition == 'invalid_rounds': bad['websites']['ClaudeTrace'].update(round_count=3, passed_count=3)
            else: bad['websites']['ClaudeTrace'].update(status=condition, passed_count=0)
            self.assertFalse(a.web_quality_eligible(bad), condition)
            self.assertFalse(a.regional_eligible(bad), condition)

    def test_failed_claude_trace_stops_download_and_merge_rejects_bypassing_it(self):
        pages = {label: {'status': 'passed', 'elapsed_ms': 100} for label in a.POST_SITES}
        pages['ClaudeTrace'] = {'status': 'failed', 'http_status': 403, 'elapsed_ms': 100}
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
        self.assertEqual(rows[0]['websites']['ClaudeTrace']['status'], 'failed')
        bundle = {'id': 'batch', 'nodes': [node]}
        part = {'bundle_id': 'batch', 'index': 0, 'count': 1, 'endpoint_count': 1, 'records': rows}
        a.merge_shards(bundle, [part], 1)
        rows[0]['download'] = {'status': 'passed', 'received_bytes': a.DOWNLOAD_BYTES, 'elapsed_ms': 1000}
        with self.assertRaises(ValueError):
            a.merge_shards(bundle, [part], 1)

    def test_default_pipeline_requests_no_claude_homepage_and_trace_pass_allows_quick_test(self):
        pages = {label: {'status': 'passed', 'elapsed_ms': 100} for label in a.POST_SITES}
        node = {'name': 'n-a', 'type': 'ss', 'server': '8.8.8.8', 'port': 443}
        pre = a.summarize_rounds([{'Google204': {'status': 'passed', 'elapsed_ms': 10}}] * 3,
            ('Google204',))['Google204']
        with patch.object(a.s, 'Core'), patch.object(a.s, 'query_exit', return_value=None), \
             patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1234})), \
             patch.object(a, 'check_sites', return_value=pages) as check:
            calls = []
            rows, _ = a.probe_pipeline([node], 'unused', Path('.'), precheck=lambda port: pre,
                probe=lambda key, pace: {'status': 'passed'},
                download=lambda port: calls.append(port) or {'status': 'failed'})
        self.assertEqual(calls, [1234])
        self.assertNotIn('Claude', rows[0]['websites'])
        self.assertEqual(rows[0]['websites']['ClaudeTrace']['round_count'], 1)
        self.assertEqual(check.call_count, 3)
        for call in check.call_args_list:
            self.assertNotIn('Claude', call.args[1])

    def test_zero_qualified_full_run_keeps_complete_audit_and_does_not_claim_publication(self):
        record = self.record(); record['websites']['ClaudeTrace'].update(status='needs_review', passed_count=0,
            attempts=[{'status': 'needs_review', 'http_status': 403, 'reason': 'challenge'}])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_attempt(root, [record], {'proxies': []}, a.REQUIRED_SITES, [], 2, '2026-10-10',
                required_traces=a.REQUIRED_TRACES)
            report = json.loads((root / 'full-test-report.json').read_text())
            self.assertEqual(report['nodes'], [record])
            self.assertEqual(report['selected_node_count'], 0)
            self.assertEqual(report['selection_outcome'], 'no_eligible_nodes_previous_subscription_retained')
            self.assertEqual(report['website_counts']['ClaudeTrace']['attempt_http_status_counts'], {'403': 1})
            self.assertEqual(report['required_traces'], ['ClaudeTrace'])
            self.assertIn('不代表通过这次页面与trace', (root / 'full-test-report.md').read_text())

    def test_full_publication_with_no_candidates_leaves_old_subscription_and_report_intact(self):
        record = self.record(); record['websites']['ClaudeTrace'].update(status='needs_review', passed_count=0)
        record['download'] = {'status': 'skipped'}
        node = {'name': record['id'], 'type': 'ss', 'server': '8.8.8.8', 'port': 443}
        bundle = {'nodes': [node], 'base': {}, 'metadata': {}, 'sources': [], 'input_count': 1,
            'rejected': [], 'services': {}, 'scope': 'all_subscriptions', 'id': 'batch'}
        with tempfile.TemporaryDirectory() as directory:
            old_cwd = os.getcwd()
            try:
                os.chdir(directory)
                root = Path('.node-work/availability'); root.mkdir(parents=True)
                (root / 'bundle.json').write_text(json.dumps(bundle))
                originals = {filename: b'previous published result\n'
                    for filename in ('优选配置.yaml', '连通性报告.json', '连通性报告.md')}
                for filename, contents in originals.items(): Path(filename).write_bytes(contents)
                with patch.object(sys, 'argv', ['availability', '--phase', 'publish', '--mihomo', 'unused']), \
                     patch.object(a, 'merge_shards', return_value=([record], 1)), \
                     patch.object(a.s, 'lookup_ip_types', return_value={}), \
                     patch.object(a.ip_reputation, 'lookup', return_value={}), \
                     patch.object(a.subprocess, 'run', side_effect=AssertionError('no empty subscription publication')):
                    a.main()
                self.assertEqual({f: Path(f).read_bytes() for f in originals}, originals)
                self.assertTrue((root / 'full-test-report.json').exists())
            finally:
                os.chdir(old_cwd)
