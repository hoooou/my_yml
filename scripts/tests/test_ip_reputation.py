import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ip_reputation as p


class ReputationTests(unittest.TestCase):
    def test_no_key_makes_no_request_and_no_fake_score(self):
        with patch.object(p.s, 'session', side_effect=AssertionError('no anonymous lookups')):
            result = p.lookup(['8.8.8.8', '8.8.8.8'], '')
        self.assertEqual(len(result), 1)
        self.assertEqual(p.purity_label({'ip_reputation': result['8.8.8.8']}), '纯净未知')

    def test_network_score_is_not_individual_abuse_and_residence_is_not_hosting_false(self):
        value = {'ip': '8.8.8.8', 'company': {'type': 'isp', 'abuser_score': '0.0183 (Elevated)'},
                 'is_datacenter': False, 'is_abuser': True}
        info = p.normalize('8.8.8.8', value)
        self.assertAlmostEqual(info['network_purity_score'], 98.17)
        self.assertEqual(p.purity_label({'ip_reputation': info}), '网段纯净98.17/有滥用')
        self.assertEqual(p.residence_label({'ip_reputation': info}), '住宅候选')
        info['is_datacenter'] = True
        self.assertEqual(p.residence_label({'ip_reputation': info}), '机房')
        self.assertEqual(p.residence_label({'ip_type': {'status': 'success', 'hosting': False}}), '非机房')
        self.assertEqual(p.residence_label({}), '住宅未知')

    def test_invalid_scores_and_mismatched_ip_remain_unknown(self):
        for raw in ('NaN', 'inf', '-0.1', '1.01', 'garbage', None):
            info = p.normalize('8.8.8.8', {'ip': '8.8.8.8', 'company': {'abuser_score': raw}})
            self.assertIsNone(info['network_purity_score'])
        self.assertEqual(p.normalize('8.8.8.8', {'ip': '1.1.1.1', 'company': {}})['status'], 'unknown')
        self.assertEqual(p.normalize('8.8.8.8', {'ip': '8.8.8.8', 'company': 'anonymous'})['status'], 'unknown')

    def test_batch_dedup_and_stop_on_quota_without_retrying(self):
        with patch.object(p.s, 'session') as session:
            client = session.return_value.__enter__.return_value
            client.post.return_value.status_code = 429
            ips = [f'8.8.{i // 250}.{i % 250 + 1}' for i in range(101)]
            result = p.lookup(ips + [ips[0]], 'secret-fixture')
        self.assertEqual(client.post.call_count, 1)
        payload = client.post.call_args.kwargs['json']
        self.assertEqual(len(payload['ips']), 100)
        self.assertEqual(payload['key'], 'secret-fixture')
        self.assertEqual(len(result), 101)
        self.assertTrue(all(r['status'] == 'unknown' for r in result.values()))
        self.assertNotIn('secret-fixture', str(result))
