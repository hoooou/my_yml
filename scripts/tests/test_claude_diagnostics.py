import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import claude_diagnostics as d


class ClaudeDiagnosticsTests(unittest.TestCase):
    def test_cohort_uses_real_trace_and_diverse_exits_without_node_names(self):
        rows = []
        for i, country in enumerate(('US', 'US', 'FR', 'DE')):
            rows.append({'id': str(i), 'exit': {'country_code': country, 'exit_ip': str(i)},
                'websites': {k: {'status': 'passed'} for k in ('Google', 'YouTube', 'ClaudeTrace')}})
        rows.append({'id': 'bad', 'exit': {'country_code': 'SG'}, 'websites': None})
        nodes = [{'name': str(i)} for i in range(4)] + [{'name': 'bad'}]
        self.assertEqual([r['id'] for r in d.choose_samples(nodes, rows, 3)], ['0', '2', '3'])

    def test_challenge_evidence_keeps_403_out_of_passed_even_when_brand_present(self):
        result = d.evidence(403, 'https://claude.ai/?secret=token#fragment',
            {'Content-Type': 'text/html', 'cf-mitigated': 'challenge', 'Set-Cookie': 'private'},
            b'<title>Just a moment...</title><html>Claude cf-chl-platform</html>')
        self.assertEqual(result['classification']['status'], 'needs_review')
        self.assertTrue(result['challenge_signals']['cf_mitigated'])
        self.assertTrue(result['challenge_signals']['cf_chl'])
        self.assertEqual(result['url'], 'https://claude.ai/')
        self.assertNotIn('Set-Cookie', result['headers'])
        self.assertNotIn('token', str(result))

    def test_region_redirect_and_larger_sample_are_recorded_without_passing_redirect(self):
        result = d.evidence(302, 'https://claude.ai/',
            {'Location': 'https://www.anthropic.com/unsupported-country?token=private'}, b'')
        self.assertEqual(result['headers']['location'], 'https://www.anthropic.com/unsupported-country')
        self.assertEqual(result['classification']['status'], 'needs_review')
        html = b'<html><head>' + b' ' * 20000 + b'<title>Claude</title></head></html>'
        result = d.evidence(200, 'https://claude.ai/', {'Content-Type': 'text/html'}, html)
        self.assertEqual(result['classification']['status'], 'failed')
        self.assertEqual(result['larger_sample_classification']['status'], 'passed')


if __name__ == '__main__':
    unittest.main()
