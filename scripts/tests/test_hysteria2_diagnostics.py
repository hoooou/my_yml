import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import hysteria2_diagnostics as d


class HysteriaDiagnosticsTests(unittest.TestCase):
    def task(self, **overrides):
        value = {'node_id': 'mobile', 'host': '8.8.8.8', 'port': 443, 'rtt_ms': 12.5,
                 'success': True, 'responded': True, 'response_bytes': 35}
        value.update(overrides)
        return {'data': {'status': 'completed', 'task_id': 'pt_test', 'result': value}}

    def test_reply_is_evidence_only_never_authenticated_or_production_passed(self):
        value = self.task(error='private credential', payload='private packet', cookie='private session')
        result = d.parse_result(value, 'mobile', '8.8.8.8', 443)
        self.assertEqual(result['status'], 'reply')
        self.assertFalse(result['protocol_verified'])
        self.assertNotIn('private', json.dumps(result))

    def test_silent_udp_and_service_errors_never_mean_failed(self):
        result = d.parse_result(self.task(success=False, responded=False, response_bytes=0),
                                'mobile', '8.8.8.8', 443)
        self.assertEqual(result['status'], 'no_reply')
        for data in ({}, {'data': {'status': 'failed'}}, None):
            self.assertEqual(d.parse_result(data, 'mobile', '8.8.8.8', 443)['status'], 'unknown')

    def test_wrong_probe_or_target_and_conflicting_flags_are_unknown(self):
        for change in ({'node_id': 'foreign'}, {'host': '1.1.1.1'}, {'port': 80},
                       {'port': '443'}, {'response_bytes': 0}, {'success': False},
                       {'rtt_ms': float('nan')}, {'response_bytes': True}):
            self.assertEqual(d.parse_result(self.task(**change), 'mobile', '8.8.8.8', 443)['status'], 'unknown')

    def test_sampling_deduplicates_endpoints_and_covers_plain_and_obfuscated(self):
        nodes = [{'name': 'a', 'type': 'hysteria2', 'server': 'one', 'port': 443},
                 {'name': 'b', 'type': 'hysteria2', 'server': 'one', 'port': 443},
                 {'name': 'c', 'type': 'hysteria2', 'server': 'two', 'port': 443, 'obfs': 'salamander'},
                 {'name': 'bad', 'type': 'hysteria2', 'server': 'three', 'port': 443},
                 {'name': 'hops', 'type': 'hysteria2', 'server': 'four', 'port': 443, 'ports': '443-500'}]
        records = [{'id': n['name'], 'precheck': {'status': 'failed' if n['name'] == 'bad' else 'passed'}} for n in nodes]
        self.assertEqual([n['name'] for n in d.choose_samples(nodes, records)], ['a', 'c'])

    def test_probe_selection_requires_domestic_online_udp_capability(self):
        nodes = [{'id': 'a', 'name': '成都移动', 'country_code': 'CN', 'status': 'active',
                  'kind': 'probe', 'capabilities': ['udp']},
                 {'id': 'b', 'name': '重庆电信', 'country_code': 'CN', 'status': 'active',
                  'kind': 'probe', 'capabilities': ['udp']}]
        for key, value in [('country_code', 'US'), ('status', 'offline'), ('capabilities', ['tcp'])]:
            bad = copy.deepcopy(nodes[0]); bad[key] = value; bad['id'] = '0'; nodes.append(bad)
        self.assertEqual([n['id'] for n in d.choose_probes({'data': {'nodes': nodes}})], ['a', 'b'])


if __name__ == '__main__':
    unittest.main()
