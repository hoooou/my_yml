import base64
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import v2rayn_subscription as v


class NativeSubscriptionTests(unittest.TestCase):
    def node(self, **fields):
        return dict(name='美国01|120ms|85Mbps|住宅|纯净度99.2%', type='http',
                    server='2001:db8::1', port=443, tls=True, **fields)

    def decode(self, node):
        line = v.render({'proxies': [node]}).strip()
        self.assertTrue(line.startswith('v2rayn://'))
        payload = line.split('/', 3)[3]
        return json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))

    def test_https_stays_native_http_with_tls_auth_and_unicode_name(self):
        node = self.node(username='u:@/中文', password='p+#/@', sni='proxy.example', **{'skip-cert-verify': True})
        result = self.decode(node)
        self.assertEqual(result['ConfigType'], 10)  # 7.24.4 native HTTP, not Custom/SOCKS
        self.assertEqual(result['ConfigVersion'], 4)
        self.assertEqual(result['CoreType'], 2)
        for source, target in [('name', 'Remarks'), ('server', 'Address'), ('port', 'Port'),
                               ('username', 'Username'), ('password', 'Password'), ('sni', 'Sni')]:
            self.assertEqual(result[target], node[source])
        self.assertEqual(result['StreamSecurity'], 'tls')
        self.assertEqual(result['AllowInsecure'], 'true')
        self.assertFalse(result['MuxEnabled'])

    def test_trojan_ws_keeps_password_host_path_and_alpn(self):
        node = self.node(password='secret')
        node.update(type='trojan', network='ws', alpn=['http/1.1'],
                    **{'ws-opts': {'headers': {'Host': 'cdn.example'}, 'path': '/socket?x=1'}})
        result = self.decode(node)
        self.assertEqual(result['ConfigType'], 6)
        self.assertEqual(result['Password'], 'secret')
        self.assertEqual(result['Alpn'], 'http/1.1')
        self.assertEqual(result['TransportExtraObj'], {'Host': 'cdn.example', 'Path': '/socket?x=1'})

    def test_country_annotation_does_not_block_or_change_native_export(self):
        node = self.node(password='secret')
        node.update(type='trojan', network='ws',
                    **{'ws-opts': {'headers': {'Host': 'cdn.example'}, 'path': '/socket'}})
        expected = v.render({'proxies': [node]})
        node['country'] = 'US'
        original = copy.deepcopy(node)
        self.assertEqual(v.render({'proxies': [node]}), expected)
        self.assertEqual(node, original)
        node['plugin'] = 'unsupported'
        with self.assertRaises(ValueError):
            v.render({'proxies': [node]})

    def test_vless_http_is_raw_http_disguise_not_removed_or_h2(self):
        node = self.node(); node.update(type='vless', tls=False, uuid='test-id', network='http',
            **{'http-opts': {'headers': {'Host': ['a.example', 'b.example']}, 'path': ['/', '/p'], 'method': 'GET'}})
        result = self.decode(node)
        self.assertEqual(result['ConfigType'], 5)
        self.assertEqual(result['Password'], 'test-id')
        self.assertEqual(result['Network'], 'raw')
        self.assertEqual(result['StreamSecurity'], '')
        self.assertEqual(result['TransportExtraObj'], {'RawHeaderType': 'http', 'Host': 'a.example,b.example', 'Path': '/,/p'})

    def test_xhttp_and_reality_keep_their_own_security_and_options(self):
        node = self.node(); node.update(type='vless', uuid='test-id', network='xhttp',
            **{'client-fingerprint': 'chrome', 'xhttp-opts': {'mode': 'auto', 'path': '/stream', 'extra': {'scMaxEachPostBytes': 100000}},
               'reality-opts': {'public-key': 'pubkey', 'short-id': '815458e4'}})
        result = self.decode(node)
        self.assertEqual(result['Network'], 'xhttp')
        self.assertEqual(result['StreamSecurity'], 'reality')
        self.assertEqual(result['ShortId'], '815458e4')
        self.assertEqual(result['PublicKey'], 'pubkey')
        self.assertEqual(json.loads(result['TransportExtraObj']['XhttpExtra']), {'scMaxEachPostBytes': 100000})

    def test_unsupported_transport_or_plugin_never_silently_degrades(self):
        for change in ({'type': 'hysteria2'}, {'network': 'h2'}, {'plugin': 'obfs'},
                       {'network': 'ws', 'ws-opts': {'headers': {'X-Custom': 'a'}}}):
            node = self.node(); node.update(change)
            before = copy.deepcopy(node)
            with self.assertRaises(ValueError): v.render({'proxies': [node]})
            self.assertEqual(node, before)
        with self.assertRaises(ValueError): v.render({'proxies': []})


if __name__ == '__main__':
    unittest.main()
