import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

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

    def test_each_domestic_probe_gets_fresh_initial_and_diagnostics_cannot_publish(self):
        node = {'name': 'sample', 'type': 'hysteria2', 'server': '8.8.8.8', 'port': 443,
                'password': 'private-authentication', 'sni': 'example.com'}
        samples = []
        class Provider:
            units = 0
            blocked = False
            def prepare(self):
                return [{'id': 'mobile', 'name': '移动'}, {'id': 'telecom', 'name': '电信'}]
            def probe(self, address, port, packet, probes):
                if packet.startswith(b'fresh-packet-'):
                    self_outer.assertEqual(len(probes), 1, 'QUIC initial cannot share its connection ID across source addresses')
                    samples.append(packet)
                return [{'probe_id': p['id'], 'status': 'reply', 'protocol_verified': False} for p in probes]
            def close(self):
                pass
        self_outer = self
        def capture(binary, root, nodes, rounds=3):
            return {'sample-initial-' + str(i): b'fresh-packet-' + str(i).encode() for i in range(rounds)}
        with patch.object(d, 'choose_samples', return_value=[node]), patch.object(d.s, 'Core'), \
             patch.object(d.a, 'precheck_204', return_value={'status': 'passed'}), \
             patch.object(d, 'capture_initials', side_effect=capture), patch.object(d, 'Provider', Provider), \
             patch.object(d, 'cloud_udp', return_value={'status': 'quic_reply'}, create=True):
            import tempfile
            with tempfile.TemporaryDirectory() as folder:
                result = d.run_diagnostic('unused', Path(folder), {'nodes': []}, {'nodes': [], 'updated_at': 'test'})
        self.assertEqual(len(samples), 6)
        self.assertEqual(len(set(samples)), 6)
        self.assertFalse(result['production_gate_ready'])
        self.assertEqual(result['nodes'][0]['domestic_entry_status'], 'unknown')
        self.assertNotIn('private-authentication', json.dumps(result))
        self.assertNotIn('fresh-packet', json.dumps(result))

    def test_cloud_control_matches_connection_ids_and_rejects_wrong_response(self):
        sent = b'\xc0\x00\x00\x00\x01\x03abc\x02xy' + b'\x00' * 1200
        valid_initial = b'\xc0\x00\x00\x00\x01\x02xy\x03def' + b'\x00' * 1200
        valid_version = b'\xc0\x00\x00\x00\x00\x02xy\x03abc\x00\x00\x00\x01'
        for reply, passed in ((valid_initial, True), (valid_version, True),
                              (valid_initial.replace(b'xy', b'zz', 1), False),
                              (valid_version[:-1], False), (b'not-quic', False)):
            with patch.object(d.socket, 'socket') as create:
                create.return_value.__enter__.return_value.recv.return_value = reply
                result = d.cloud_udp('8.8.8.8', 443, sent, {})
            self.assertEqual(result['protocol_verified'], passed)

    def test_native_header_validation_includes_salamander_and_rejects_reserved_version(self):
        packet = b'\xc0\x00\x00\x00\x01\x03abc\x02xy' + b'\x00' * 1200
        node = {'obfs': 'salamander', 'obfs-password': 'private-key'}
        self.assertTrue(d.initial_packet_valid(packet, {}))
        self.assertTrue(d.initial_packet_valid(d.obfuscate(packet, node), node))
        self.assertFalse(d.initial_packet_valid(d.version_packet({}), {}))
        self.assertFalse(d.initial_packet_valid(b'not-quic', {}))


if __name__ == '__main__':
    unittest.main()
