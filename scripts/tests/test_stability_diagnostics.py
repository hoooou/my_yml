import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import stability_diagnostics as d
from test_stability import evidence


class DiagnosticCandidatesTests(unittest.TestCase):
    def test_batch_accepts_continuous_evidence_and_prioritizes_later_collapse(self):
        from test_continuous_stability import evidence as continuous_evidence
        import continuous_stability as cs
        rows, nodes = [], []
        for i in range(14):
            result = continuous_evidence()
            if i < 10:
                for sample in result['attempts'][8:]:
                    sample['sites']['Google204'].update(status='failed', error_type='ReadTimeout')
                result = cs.summarize(result['attempts'], 0)
            rows.append({'id': 'n-' + str(i), 'stability': result,
                         'exit': {'country_code': str(i % 4)}})
            nodes.append({'name': rows[-1]['id'], 'type': 'http' if i < 12 else 'vless'})
        chosen, mapping = d.batch_candidates({'nodes': rows}, {'nodes': nodes})
        self.assertEqual(len(chosen), 12)
        self.assertEqual([kind for _, kind in chosen].count('failed_HTTPS'), 8)
        self.assertEqual([kind for _, kind in chosen].count('passed_HTTP_control'), 2)
        self.assertEqual([kind for _, kind in chosen].count('passed_other_protocol_control'), 2)

    def test_batch_samples_include_never_published_first_round_failures(self):
        rows, nodes = [], []
        for i in range(16):
            result = evidence()
            if i < 12:
                for attempt in result['attempts']:
                    attempt['sites']['Google204'].update(status='failed', error_type='ReadTimeout')
                result['status'] = 'failed'
            rows.append({'id': 'n-' + str(i), 'stability': result, 'exit': {'country_code': str(i % 4)}})
            nodes.append({'name': rows[-1]['id'], 'type': 'http' if i < 14 else 'vless',
                          'password': 'PRIVATE'})
        chosen, mapping = d.batch_candidates({'nodes': rows}, {'nodes': nodes})
        self.assertEqual(len(chosen), 12)
        self.assertEqual([kind for _, kind in chosen].count('failed_HTTPS'), 8)
        self.assertEqual(len({r['exit']['country_code'] for r, _ in chosen[:4]}), 4)
        self.assertTrue(all(r['id'] in mapping for r, _ in chosen))
        self.assertTrue(all('name' not in r for r, _ in chosen))

    def test_independent_curl_preserves_certificate_checks_and_exact_204(self):
        def run(command, **kwargs):
            self.assertEqual(command[:2], ['curl', '--disable'])
            self.assertNotIn('-k', command); self.assertNotIn('--insecure', command)
            self.assertNotIn('--location', command)
            self.assertEqual(command[command.index('--max-time') + 1], '6')
            return subprocess.CompletedProcess(command, 0, json.dumps({'http_code': 204,
                'ssl_verify_result': 0, 'num_redirects': 0, 'url_effective': d.SITES['Google204'],
                'size_download': 0, 'time_total': .4, 'time_connect': .1,
                'time_appconnect': .2, 'time_starttransfer': .4}), '')
        with patch.object(d.subprocess, 'run', side_effect=run):
            self.assertEqual(d.curl_204(1234)['status'], 'passed')

    def test_alternate_target_head_and_redirect_are_explicit(self):
        target = 'https://cp.cloudflare.com/'
        def run(command, **kwargs):
            self.assertIn('--head', command)
            self.assertEqual(command[-1], target)
            self.assertNotIn('--insecure', command)
            return subprocess.CompletedProcess(command, 0, json.dumps({'http_code': 301,
                'ssl_verify_result': 0, 'num_redirects': 0, 'url_effective': target,
                'size_download': 0, 'time_total': .4, 'time_connect': .1,
                'time_appconnect': .2, 'time_starttransfer': .4}), '')
        with patch.object(d.subprocess, 'run', side_effect=run):
            result = d.curl_204(1234, target, 'HEAD')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['method'], 'HEAD')
        with self.assertRaises(ValueError):
            d.curl_204(1234, 'https://example.invalid/')

    def test_failed_nodes_resolved_from_history_and_sample_is_bounded(self):
        rows = []
        nodes = []
        for i in range(18):
            row = {'id': 'n-' + str(i), 'name': 'old-' + str(i), 'stability': evidence()}
            if i < 12:
                row['stability']['status'] = 'failed'
                row['stability']['attempts'][1]['sites']['Google204']['status'] = 'failed'
            rows.append(row)
            nodes.append({'name': row['name'], 'type': 'http' if i < 15 else 'vless'})
        current = copy.deepcopy(rows)
        for row in current[:12]:
            row.pop('name')
        selected, mapping = d.candidates({'nodes': current}, [({'proxies': nodes}, {'nodes': rows})])
        self.assertEqual(len(selected), 12)
        self.assertEqual([k for _, k in selected].count('collapsed_HTTPS'), 8)
        self.assertEqual(mapping[selected[0][0]['id']]['name'], selected[0][0]['id'])


if __name__ == '__main__':
    unittest.main()
