import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mobile_pilot as pilot


def probe(received=3, asn=9808, country='CN'):
    return {'probe': {'country': country, 'asn': asn, 'city': 'Shanghai'},
            'result': {'status': 'finished', 'resolvedAddress': '8.8.8.8',
                       'stats': {'total': 3, 'rcv': received, 'loss': round((3-received)*100/3, 1),
                                 'avg': 50 if received else None}}}


class MobilePilotTests(unittest.TestCase):
    def test_two_mobile_probes_required_and_wrong_network_is_unknown(self):
        for results, expected in [([probe(), probe()], 'passed'),
                                  ([probe(0), probe(0)], 'failed'),
                                  ([probe(2), probe()], 'unstable'),
                                  ([probe()], 'unknown'),
                                  ([probe(), probe(asn=4134)], 'unknown'),
                                  ([probe(), probe(country='US')], 'unknown')]:
            result = pilot.parse_mobile_result({'status': 'finished', 'results': results}, 'sample')
            self.assertEqual(result['status'], expected)
        malformed = probe(); malformed['result']['stats']['rcv'] = True
        result = pilot.parse_mobile_result({'status': 'finished', 'results': [malformed, probe()]}, 'sample')
        self.assertEqual(result['status'], 'unknown')

    def test_udp_nodes_are_not_classified_by_tcp_or_sent_to_api(self):
        with patch.object(pilot.s, 'session') as session:
            result = pilot.check_mobile({'type': 'hysteria2', 'server': '8.8.8.8', 'port': 443})
        self.assertEqual(result['status'], 'unknown')
        session.assert_not_called()

    def test_challenges_and_access_denials_do_not_claim_chatgpt_works(self):
        for status, body in [(403, b'Forbidden'), (200, b'<html>ChatGPT just a moment</html>'),
                             (200, b'<html>ChatGPT cf-chl-test</html>')]:
            result = pilot.classify_page('ChatGPT', status, 'https://chatgpt.com/', 'text/html', body)
            self.assertEqual(result['status'], 'needs_review')
        result = pilot.classify_page('YouTube', 200, 'https://www.youtube.com/', 'text/html', b'<html>YouTube</html>')
        self.assertEqual(result['status'], 'passed')
        result = pilot.classify_page('YouTube', 200, 'https://unrelated.example/', 'text/html', b'YouTube')
        self.assertEqual(result['status'], 'needs_review')

    def test_candidate_group_excludes_failed_and_unknown_but_controls_stay(self):
        records = []
        for index, mobile, download in [(1, 'passed', 'passed'), (2, 'failed', 'passed'),
                                        (3, 'unknown', 'passed'), (4, 'passed', 'failed')]:
            records.append({'id': f'n-{index:012d}', 'source_country': 'HK', 'cloud_latency_ms': 20,
                            'mobile': {'status': mobile, 'latency_ms': 50},
                            'download': {'status': download, 'speed_mib_s': 2},
                            'websites': {'Google': {'status': 'passed'}}})
        base = {'dns': {'default-nameserver': ['223.5.5.5']}, 'rules': ['MATCH,DIRECT'], 'rule-providers': {}}
        original = copy.deepcopy(base)
        mapping = {r['id']: {'name': r['id'], 'type': 'ss', 'server': '8.8.8.8', 'port': 443} for r in records}
        config, candidates = pilot.render_pilot(base, records, mapping)
        self.assertEqual(candidates, [records[0]['id']])
        groups = {g['name']: g['proxies'] for g in config['proxy-groups']}
        self.assertEqual(groups['📶 移动入口候选'], [records[0]['name']])
        self.assertEqual(len(groups['🧪 全部样本']), 4)
        self.assertEqual(config['rules'], ['MATCH,🚀 全局选择'])
        self.assertEqual(base, original)
        valid = {p['name'] for p in config['proxies']} | set(groups) | {'DIRECT', 'REJECT'}
        self.assertTrue(all(name in valid for proxies in groups.values() for name in proxies))
