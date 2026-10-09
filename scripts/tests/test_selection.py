import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import select_nodes as selection


class Response:
    def __init__(self, text='', chunks=None, data=None, headers=None, status_code=200):
        self.text = text
        self.chunks = chunks or []
        self.data, self.headers, self.status_code = data, headers or {}, status_code

    def json(self):
        return self.data

    def raise_for_status(self):
        pass

    def iter_content(self, size):
        return iter(self.chunks)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class Client:
    def __init__(self, responses):
        self.responses = iter(responses)

    def get(self, *_args, **_kwargs):
        return next(self.responses)

    def post(self, *_args, **_kwargs):
        return next(self.responses)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class SelectionTests(unittest.TestCase):
    def test_dedup_keeps_distinct_credentials_and_tracks_sources(self):
        node = {'name': '广告名', 'type': 'ss', 'server': 'example.com', 'port': 443,
                'cipher': 'aes-128-gcm', 'password': 'one'}
        other = {**node, 'name': '另一个名称', 'password': 'two'}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for provider, nodes in [('a1', [node]), ('a2', [node, other])]:
                selection.dump(root / (provider + '.txt'), {'proxies': nodes})
            nodes, metadata, _ = selection.collect({'proxy-providers': {'a1': {}, 'a2': {}}}, root, root)
        self.assertEqual(len(nodes), 2)
        self.assertEqual(sorted(len(m['sources']) for m in metadata.values()), [1, 2])
        self.assertTrue(all(n['name'].startswith('n-') for n in nodes))

    def test_new_sources_merge_and_normalize_without_importing_source_rules(self):
        node = {'name': 'old', 'type': 'vmess', 'server': 'EXAMPLE.COM.', 'port': '443',
                'uuid': 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'}
        normalized = {**node, 'server': 'example.com', 'port': 443,
                      'uuid': node['uuid'].lower()}
        normalized.pop('name')
        different = {**normalized, 'uuid': 'ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee'}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selection.dump(root / 'original.txt', {'proxies': [node]})
            selection.dump(root / 'extra.txt', {'proxies': [normalized, different],
                                                'rules': ['MATCH,DIRECT'], 'mixed-port': 9999})
            base = {'proxy-providers': {'original': {}}}
            nodes, metadata, sources = selection.collect(base, root, root, {'extra': {}})
        self.assertEqual(len(nodes), 2)
        self.assertEqual(sources[1]['duplicates'], 1)
        self.assertEqual(sources[1]['unique_added'], 1)
        self.assertEqual(sum(s['downloaded'] for s in sources), 3)
        self.assertEqual(sorted(len(m['sources']) for m in metadata.values()), [1, 2])
        self.assertEqual({n['server'] for n in nodes}, {'example.com'})
        self.assertTrue(all(n['port'] == 443 for n in nodes))
        self.assertTrue(all('rules' not in n and 'mixed-port' not in n for n in nodes))
        self.assertNotIn('extra', base['proxy-providers'])

    def test_bad_source_and_unusable_nodes_do_not_discard_good_source(self):
        node = {'type': 'ss', 'server': 'example.com', 'port': 443, 'password': 'one'}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'bad.txt').write_text('proxies: [unterminated')
            selection.dump(root / 'good.txt', {'proxies': [node, {**node, 'dialer-proxy': 'external'},
                                                        {**node, 'port': 0}, 'not a node']})
            nodes, _, sources = selection.collect({'proxy-providers': {'bad': {}, 'good': {}}}, root, root)
        self.assertEqual(len(nodes), 1)
        self.assertNotEqual(sources[0]['status'], 'ok')
        self.assertEqual(sources[1]['skipped'], 3)
        self.assertEqual(sources[1]['status'], 'ok')

    def test_source_manifest_rejects_duplicate_ids_and_honors_disabled_entries(self):
        entry = {'id': 'extra', 'url': 'https://example.com/nodes.yaml'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sources.yaml'
            selection.dump(path, {'sources': [entry, {**entry, 'enabled': False}]})
            self.assertEqual(list(selection.load_sources(path)), ['extra'])
            selection.dump(path, {'sources': [entry, entry]})
            with self.assertRaisesRegex(ValueError, '重复'):
                selection.load_sources(path)

    def test_region_comes_from_trace_and_file_speed_is_conservative(self):
        body = b'x' * selection.FILE_BYTES
        client = Client([Response('ip=8.8.8.8\nloc=JP\n'), Response(chunks=[body])])
        with patch.object(selection, 'session', return_value=client), patch.object(selection.time, 'perf_counter', side_effect=[0, .5, 1]):
            result = selection.verify_exit(12345, {'exit_ip': '8.8.8.8', 'country_code': 'JP', 'file_speed_mib_s': 2.5}, hashlib.sha256(body).hexdigest())
        self.assertEqual(result['country_code'], 'JP')
        self.assertEqual(result['exit_ip'], '8.8.8.8')
        self.assertEqual(result['speed_mib_s'], 2.5)

    def test_incomplete_file_and_replaced_content_are_rejected(self):
        for body, expected, message in [(b'x' * 1024, None, '未完整下载'),
                                        (b'x' * selection.FILE_BYTES, 'wrong', '内容与直连对照不一致')]:
            client = Client([Response(chunks=[body])])
            with patch.object(selection.time, 'perf_counter', side_effect=[0, .5, 1]):
                with self.assertRaisesRegex(ValueError, message):
                    selection.download_file(client, expected)

    def test_region_or_ip_change_after_classification_is_rejected(self):
        record = {'exit_ip': '8.8.8.8', 'country_code': 'JP', 'file_speed_mib_s': 2.5}
        for trace in ['ip=8.8.8.8\nloc=US\n', 'ip=1.1.1.1\nloc=JP\n']:
            with patch.object(selection, 'session', return_value=Client([Response(trace)])):
                with self.assertRaisesRegex(ValueError, '发生变化'):
                    selection.verify_exit(12345, record, 'unused')

    def test_each_region_has_own_quota_and_non_datacenter_ips_are_unique(self):
        def row(name, country, speed, ip, hosting=True):
            return {'id': name, 'country_code': country, 'speed_mib_s': speed, 'latency_ms': 100,
                    'exit_ip': ip, 'ip_type': {'status': 'success', 'hosting': hosting}}
        records = [row('n-us1', 'US', 100, '8.8.8.1'), row('n-us2', 'US', 90, '8.8.8.2'),
                   row('n-us3', 'US', 80, '8.8.8.3', False), row('n-us4', 'US', 70, '8.8.8.3', False),
                   row('n-us5', 'US', 60, '8.8.8.5', False), row('n-jp1', 'JP', 5, '1.1.1.1'),
                   row('n-jp2', 'JP', 4, '1.1.1.2'), row('n-jp3', 'JP', 3, '1.1.1.3')]
        selected, regional, non_dc = selection.select_rankings(records, 2, 2)
        self.assertEqual(regional, {'US': ['n-us1', 'n-us2'], 'JP': ['n-jp1', 'n-jp2']})
        self.assertEqual(non_dc, ['n-us3', 'n-us5'])
        self.assertEqual(len(selected), 6)
        base = {'dns': {'default-nameserver': ['223.5.5.5']}, 'rules': ['MATCH,🚀 全局选择'], 'rule-providers': {}}
        config = selection.render_config(base, selected, {r['id']: {'name': r['id']} for r in records}, regional, non_dc)
        groups = {g['name']: g['proxies'] for g in config['proxy-groups']}
        self.assertEqual(len(groups['美国']), 2)
        self.assertEqual(len(groups['日本']), 2)
        self.assertEqual(len(groups['🏠 非机房 IP']), 2)
        self.assertEqual(len(config['proxies']), 6)

    def test_unknown_ip_type_never_enters_non_datacenter_group(self):
        records = [{'id': 'n-a', 'country_code': 'JP', 'speed_mib_s': 3, 'latency_ms': 100,
                    'exit_ip': '8.8.8.8', 'ip_type': {'status': 'success'}},
                   {'id': 'n-b', 'country_code': 'JP', 'speed_mib_s': 2, 'latency_ms': 100,
                    'exit_ip': '1.1.1.1', 'ip_type': {'status': 'unknown', 'hosting': False}}]
        _, _, non_dc = selection.select_rankings(records, 30, 30)
        self.assertEqual(non_dc, [])

    def test_ip_lookup_uses_explicit_boolean_and_stops_on_rate_limit(self):
        response = Response(data=[{'query': '8.8.8.8', 'status': 'success', 'hosting': False},
                                  {'query': '1.1.1.1', 'status': 'success'}])
        with patch.object(selection, 'session', return_value=Client([response])):
            result = selection.lookup_ip_types(['8.8.8.8', '1.1.1.1', '8.8.8.8'])
        self.assertIs(result['8.8.8.8']['hosting'], False)
        self.assertEqual(result['1.1.1.1']['status'], 'unknown')
        client = Client([Response(status_code=429)])
        with patch.object(selection, 'session', return_value=client):
            result = selection.lookup_ip_types(['8.8.8.8'])
        self.assertEqual(result['8.8.8.8']['status'], 'unknown')

    def test_all_classified_nodes_are_tested_even_if_region_quota_is_small(self):
        records = [{'id': f'n-{i}', 'country_code': 'JP', 'latency_ms': 100} for i in range(7)]
        class FakeCore:
            def __init__(self, *_): pass
            def __enter__(self): return self
            def __exit__(self, *_): pass
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(selection, 'Core', FakeCore), patch.object(selection, 'measure_file', side_effect=lambda _b, _r, n, _m: {'id': n['id']}), patch.object(selection, 'verify_exit', side_effect=lambda _p, r, _h: {**r, 'speed_mib_s': 5}):
                verified, summaries = selection.measure_regions('/core', '/tool', Path(directory), records,
                    {r['id']: r for r in records}, {r['id']: {'sources': ['test']} for r in records},
                    {'max_latency_ms': 1000, 'file_sha256': 'hash', 'per_region_limit': 2})
        self.assertEqual(len(verified), 7)
        self.assertEqual(summaries[0]['file_tested'], 7)

    def test_generated_groups_and_rules_reference_existing_targets(self):
        base = {'mixed-port': 7890, 'dns': {'default-nameserver': ['223.5.5.5', '192.168.70.49']},
                'rules': ['RULE-SET,google,🚀 全局选择', 'DOMAIN-SUFFIX,office.com,DIRECT', 'MATCH,🚀 全局选择'],
                'rule-providers': {'google': {'type': 'http'}, 'unused': {'type': 'http'}}}
        original = copy.deepcopy(base)
        record = {'id': 'n-abc123def456', 'country_code': 'JP', 'speed_mib_s': 2,
                  'latency_ms': 100}
        config = selection.render_config(base, [record], {record['id']: {'name': record['id'], 'server': 'example.com'}})
        targets = {'DIRECT', 'REJECT'} | {g['name'] for g in config['proxy-groups']} | {p['name'] for p in config['proxies']}
        for group in config['proxy-groups']:
            self.assertTrue(set(group['proxies']).issubset(targets))
            self.assertTrue(group['proxies'])
        self.assertEqual(config['rules'], base['rules'])
        self.assertEqual(set(config['rule-providers']), {'google'})
        self.assertEqual(config['dns']['default-nameserver'], ['223.5.5.5'])
        self.assertEqual(base, original)

    def test_failed_tool_does_not_reuse_stale_result(self):
        node = {'name': 'n-test', 'server': 'example.com'}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selection.dump(root / 'n-test-tested.yaml', {'proxies': [node]})
            with patch.object(selection.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'failed')):
                result = selection.measure_file('/fake/tool', root, node, 1000)
            self.assertIsNone(result)
            self.assertFalse((root / 'n-test-tested.yaml').exists())


if __name__ == '__main__':
    unittest.main()
