import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ip_reputation as p


class ReputationTests(unittest.TestCase):
    def test_no_key_falls_back_to_free_source_and_never_fakes_a_score(self):
        with patch.object(p.s, 'session') as session:
            client = session.return_value.__enter__.return_value
            client.post.return_value.json.return_value = [
                {'query': '8.8.8.8', 'status': 'success', 'hosting': False, 'proxy': False, 'mobile': False}]
            result = p.lookup(['8.8.8.8', '8.8.8.8'], '', use_cache=False)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['8.8.8.8']['provider'], 'ip-api.com')
        self.assertEqual(p.residence_label({'ip_reputation': result['8.8.8.8']}), '住宅候选')
        self.assertEqual(p.purity_label({'ip_reputation': result['8.8.8.8']}), '纯净未知')
        self.assertIsNone(result['8.8.8.8']['network_purity_score'])

    def test_failed_primary_lookups_are_retried_once_on_the_free_source(self):
        with patch.object(p.s, 'session') as session:
            client = session.return_value.__enter__.return_value
            client.post.return_value.json.return_value = [
                {'query': '8.8.8.8', 'status': 'success', 'hosting': True, 'proxy': False, 'mobile': False}]
            client.post.return_value.status_code = 403
            result = p.lookup(['8.8.8.8'], 'secret-fixture', use_cache=False)
        self.assertEqual(client.post.call_count, 2)
        self.assertEqual(client.post.call_args_list[0].kwargs['json']['key'], 'secret-fixture')
        self.assertEqual(result['8.8.8.8']['provider'], 'ip-api.com')

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
            result = p.lookup(ips + [ips[0]], 'secret-fixture', use_cache=False)
        # 主源 429 后不再重试；之后两批是免费备用源（101 个 IP 按 100 分两批），同样被拒，仍然未知。
        self.assertEqual(client.post.call_count, 3)
        payload = client.post.call_args_list[0].kwargs['json']
        self.assertEqual(len(payload['ips']), 100)
        self.assertEqual(payload['key'], 'secret-fixture')
        self.assertEqual(len(result), 101)
        self.assertTrue(all(r['status'] == 'unknown' for r in result.values()))
        self.assertNotIn('secret-fixture', str(result))

    def test_repeat_lookups_reuse_the_cache_without_requests(self):
        import json, tempfile
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(p, 'ROOT', Path(folder)):
                with patch.object(p.s, 'session') as session:
                    client = session.return_value.__enter__.return_value
                    client.post.return_value.json.return_value = [
                        {'query': '8.8.8.8', 'status': 'success', 'hosting': True, 'proxy': False, 'mobile': False}]
                    first = p.lookup(['8.8.8.8'], '')
                    calls = client.post.call_count
                    second = p.lookup(['8.8.8.8'], '')
                entries = json.loads((Path(folder) / p.CACHE_FILE).read_text())['entries']
        self.assertEqual(calls, 1)
        self.assertEqual(client.post.call_count, calls)
        self.assertEqual(first['8.8.8.8']['status'], 'success')
        self.assertEqual(second['8.8.8.8']['status'], 'success')
        self.assertEqual(p.residence_label({'ip_reputation': second['8.8.8.8']}), '机房')
        self.assertIn('8.8.8.8', entries)

    def test_stale_cache_entries_are_queried_again(self):
        import json, tempfile
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / p.CACHE_FILE).write_text(json.dumps({'entries': {
                '8.8.8.8': {'status': 'success', 'checked_at': '2020-01-01T00:00:00+08:00'}}}))
            with patch.object(p, 'ROOT', root):
                with patch.object(p.s, 'session') as session:
                    client = session.return_value.__enter__.return_value
                    client.post.return_value.json.return_value = [
                        {'query': '8.8.8.8', 'status': 'success', 'hosting': False, 'proxy': True, 'mobile': False}]
                    result = p.lookup(['8.8.8.8'], '')
        self.assertEqual(client.post.call_count, 1)
        self.assertIs(result['8.8.8.8']['is_proxy'], True)

