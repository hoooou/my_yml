from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import header_diagnostics as d
import mobile_pilot as p


class HeaderDiagnosticsTests(unittest.TestCase):
    def test_every_daily_destination_compared_three_times_with_alternating_order(self):
        self.assertEqual(set(d.LABELS), set(p.OVERSEAS_SITES) | set(p.CONNECTIVITY_SITES))
        self.assertEqual(len(d.LABELS), 29)
        calls = []
        def checked(port, label, url, **kwargs):
            nav = kwargs['request_headers'].get('Sec-Fetch-Mode') == 'navigate'
            calls.append(nav)
            return {'status': 'passed' if nav else 'failed', 'http_status': 200 if nav else 400,
                    'elapsed_ms': 200, 'ttfb_ms': 100}
        with patch.object(p, 'check_site', side_effect=checked):
            item = d.inspect(1234, 'Facebook')
        self.assertEqual(calls, [False, True, True, False, False, True])
        self.assertEqual(item['variants']['original']['accepted_count'], 0)
        self.assertEqual(item['variants']['navigation']['accepted_count'], 3)

    def test_sample_pool_requires_current_input_and_prior_preconditions(self):
        def row(i, country, score):
            return {'id': str(i), 'precheck': {'status': 'passed'}, 'upload_precheck': {'status': 'passed'},
                    'exit': {'exit_ip': str(i), 'country_code': country},
                    'websites': {str(n): {'status': 'passed'} for n in range(score)}}
        rows = [row(1, 'US', 25), row(2, 'US', 24), row(3, 'JP', 23), row(4, 'DE', 29)]
        selected = d.choose_samples({'nodes': [{'name': str(i)} for i in (1, 2, 3)]}, {'nodes': rows})
        self.assertEqual([r['id'] for r in selected], ['1', '3'])
        rows[2]['upload_precheck']['status'] = 'failed'
        self.assertEqual([r['id'] for r in d.choose_samples(
            {'nodes': [{'name': str(i)} for i in (1, 2, 3)]}, {'nodes': rows})], ['1', '2'])


if __name__ == '__main__':
    unittest.main()
