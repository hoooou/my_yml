import copy
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
    def __init__(self, text='', chunks=None):
        self.text = text
        self.chunks = chunks or []

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

    def test_region_comes_from_exit_trace_and_speed_is_conservative(self):
        client = Client([Response('ip=203.0.113.5\nloc=JP\n'), Response(chunks=[b'x' * (4 * 1024 * 1024)])])
        with patch.object(selection, 'session', return_value=client), patch.object(selection.time, 'perf_counter', side_effect=[0, .5, 1]):
            result = selection.verify_exit(12345, {'file_speed_mib_s': 2.5})
        self.assertEqual(result['country_code'], 'JP')
        self.assertEqual(result['exit_ip'], '203.0.113.5')
        self.assertEqual(result['speed_mib_s'], 2.5)

    def test_incomplete_file_is_rejected(self):
        client = Client([Response('ip=203.0.113.5\nloc=US\n'), Response(chunks=[b'x' * 1024])])
        with patch.object(selection, 'session', return_value=client), patch.object(selection.time, 'perf_counter', side_effect=[0, .5, 1]):
            with self.assertRaisesRegex(ValueError, '未完整下载'):
                selection.verify_exit(12345, {'file_speed_mib_s': 2.5})

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
