import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a


class AvailabilityTests(unittest.TestCase):
    def test_tcp_connection_failure_is_distinct_from_api_errors(self):
        self.assertEqual(a.parse_xxapi({'code': -2, 'msg': '连接失败'}, 'example.com', 443)['status'], 'failed')
        for data in [None, [], {'code': 500, 'msg': 'error'}, {'code': -2, 'msg': 'quota'},
                     {'code': 200, 'data': {'address': 'other.com', 'port': 443, 'ping': '2ms'}},
                     {'code': 200, 'data': {'address': 'example.com', 'port': 80, 'ping': '2ms'}},
                     {'code': 200, 'data': {'address': 'example.com', 'port': 443, 'ping': 'NaNms'}}]:
            self.assertEqual(a.parse_xxapi(data, 'example.com', 443)['status'], 'unknown')
        result = a.parse_xxapi({'code': 200, 'data': {'address': 'example.com', 'port': '443', 'ping': '21ms'}}, 'example.com', 443)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['latency_ms'], 21)

    def test_all_unique_tcp_endpoints_tested_and_shared_credentials_not_dropped(self):
        nodes = [{'name': 'n-1', 'type': 'ss', 'server': '8.8.8.8', 'port': 443, 'password': 'a'},
                 {'name': 'n-2', 'type': 'ss', 'server': '8.8.8.8', 'port': 443, 'password': 'b'},
                 {'name': 'n-3', 'type': 'ss', 'server': '1.1.1.1', 'port': 80},
                 {'name': 'n-4', 'type': 'hysteria2', 'server': '1.1.1.1', 'port': 443}]
        tested = []
        def probe(key, pace):
            tested.append(key)
            return {'status': 'passed' if key[1] == 443 else 'failed'}
        records, count = a.classify_all(nodes, probe=probe)
        self.assertEqual(set(tested), {('8.8.8.8', 443), ('1.1.1.1', 80)})
        self.assertEqual(count, 2)
        self.assertEqual(len(records), 4)
        self.assertEqual([r['entry']['status'] for r in records], ['passed', 'passed', 'failed', 'unknown'])

    def test_failed_and_unknown_nodes_never_reach_websites_or_downloads(self):
        with patch.object(a.s, 'download_file', side_effect=AssertionError('download forbidden')), \
             patch.object(a.s, 'measure_file', side_effect=AssertionError('download forbidden')), \
             patch.object(a.s, 'query_exit', return_value={'exit_ip': '8.8.8.8', 'country_code': 'US'}), \
             patch.object(a.time, 'sleep'):
            calls = []
            def websites(port):
                calls.append(port)
                return {label: {'status': 'passed', 'elapsed_ms': 20} for label in a.SITES}
            for status in ('failed', 'unknown'):
                r = a.check_repeated(1234, {'entry': {'status': status}}, site_check=websites)
                self.assertNotIn('websites', r)
            r = a.check_repeated(1234, {'id': 'n-a', 'entry': {'status': 'passed'}}, site_check=websites)
            self.assertEqual(calls, [1234]*3)
            self.assertTrue(all(v['round_count'] == v['passed_count'] == 3 for v in r['websites'].values()))

    def test_intermittent_page_and_challenge_never_mark_stable(self):
        rounds = [{label: {'status': 'passed', 'elapsed_ms': 20} for label in a.SITES} for _ in range(3)]
        rounds[1]['Google']['status'] = 'failed'
        rounds[2]['ChatGPT']['status'] = 'needs_review'
        result = a.summarize_rounds(rounds)
        self.assertEqual(result['Google']['status'], 'unstable')
        self.assertEqual(result['Google']['passed_count'], 2)
        self.assertEqual(result['ChatGPT']['status'], 'needs_review')
        self.assertEqual(result['YouTube']['status'], 'passed')

    def test_all_categories_remain_importable_for_local_comparison(self):
        records = [{'id': 'n-' + str(i)*12, 'entry': {'status': status}, 'websites': None, 'exit': None}
                   for i, status in [(1, 'passed'), (2, 'failed'), (3, 'unknown')]]
        records[0]['websites'] = {k: {'status': 'passed', 'passed_count': 3} for k in a.SITES}
        records[0]['exit'] = {'country_code': 'HK', 'exit_ip': '8.8.8.8'}
        records[0]['ip_type'] = {'status': 'unknown', 'hosting': None}
        mapping = {r['id']: {'name': r['id'], 'type': 'http', 'server': '8.8.8.8', 'port': 80} for r in records}
        base = {'dns': {}, 'rules': ['MATCH,🚀 全局选择'], 'rule-providers': {}}
        original = copy.deepcopy(base)
        config = a.render_comparison(base, records, mapping)
        self.assertEqual(len(config['proxies']), 3)
        groups = {g['name']: g['proxies'] for g in config['proxy-groups']}
        for group in ('📶 TCP通', '⛔ TCP不通', '🔎 TCP未验证'):
            self.assertEqual(len(groups[group]), 1)
            self.assertNotEqual(groups[group], ['REJECT'])
        self.assertEqual(groups['🏠 非机房 IP'], ['REJECT'])
        self.assertEqual(groups['✅ 三站稳定'], [records[0]['name']])
        self.assertEqual(base, original)
        valid = {p['name'] for p in config['proxies']} | set(groups) | {'DIRECT', 'REJECT'}
        self.assertTrue(all(name in valid for proxies in groups.values() for name in proxies))
        self.assertTrue(all('MiB' not in n['name'] for n in config['proxies']))


if __name__ == '__main__':
    unittest.main()
