import copy
import os
from unittest.mock import patch, MagicMock
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import untested_subscription as u
import v2rayn_subscription as v
import requests


class UntestedSubscriptionTests(unittest.TestCase):
    def config(self):
        return {'proxies': [{'name': 'tested', 'type': 'http', 'server': 'a.example', 'port': 443}],
                'proxy-groups': [{'name': '🚀 全局选择', 'type': 'select', 'default-selected': '⭐ 综合优选',
                                  'proxies': ['⭐ 综合优选', 'DIRECT']},
                                 {'name': '⭐ 综合优选', 'type': 'url-test', 'proxies': ['tested']}],
                'dns': {'enable': True}, 'rules': ['MATCH,🚀 全局选择']}

    def node(self, name='香港01'):
        return {'name': name, 'type': 'trojan', 'server': 'proxy.example', 'port': 443,
                'password': 'secret', 'sni': 'tls.example', 'skip-cert-verify': False}

    def test_authorized_pool_is_separate_and_does_not_change_measurement_pools(self):
        config = self.config(); before = copy.deepcopy(config)
        result, info = u.append_nodes(config, [self.node()])
        self.assertEqual(config, before)
        self.assertEqual(result['proxy-groups'][1], before['proxy-groups'][1])
        self.assertEqual(result['dns'], before['dns']); self.assertEqual(result['rules'], before['rules'])
        self.assertEqual(result['proxy-groups'][-1], {'name': u.GROUP, 'type': 'select', 'proxies': ['🍓 香港01']})
        self.assertFalse(info['tested']); self.assertEqual(info['added_node_count'], 1)
        self.assertIn(u.GROUP, result['proxy-groups'][0]['proxies'])
        self.assertEqual(result['proxy-groups'][0]['default-selected'], '⭐ 综合优选')
        self.assertEqual(len(v.render(result).splitlines()), 2)

    def test_duplicate_definitions_reuse_existing_nodes_and_colliding_names_stay_unique(self):
        first = self.node('same'); second = self.node('same'); second['server'] = 'other.example'
        duplicate = dict(self.config()['proxies'][0], name='duplicate')
        result, info = u.append_nodes(self.config(), [first, first, second, duplicate])
        names = result['proxy-groups'][-1]['proxies']
        self.assertEqual(names, ['🍓 same', '🍓 same (2)', 'tested'])
        self.assertEqual(len(result['proxies']), 3)
        self.assertEqual(info['duplicates'], 2)

    def test_not_configured_never_fetches_and_invalid_node_never_silently_disappears(self):
        with patch.dict(os.environ, {'UNTESTED_SUBSCRIPTION_URL': ''}), patch.object(u, 'fetch_nodes') as fetch:
            result, info = u.append_from_env(self.config()); fetch.assert_not_called()
        self.assertEqual(info['node_count'], 0)
        with self.assertRaises(ValueError): u.append_nodes(self.config(), [{'name': 'invalid'}])

    def test_fetch_failure_does_not_leak_secret_url_or_credentials(self):
        with patch.object(u.requests, 'Session') as client:
            client.return_value.__enter__.return_value.get.side_effect = requests.RequestException('token=very-secret')
            with self.assertRaises(ValueError) as caught: u.fetch_nodes('https://example.com/sub?token=very-secret')
        self.assertNotIn('very-secret', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
