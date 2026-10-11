import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a


class PublishedHistoryTests(unittest.TestCase):
    def test_prepare_retests_previous_published_candidate_missing_from_upstream(self):
        with tempfile.TemporaryDirectory() as directory:
            cwd = os.getcwd()
            try:
                os.chdir(directory)
                def git(*args):
                    return subprocess.check_output(['git', *args], stderr=subprocess.DEVNULL)
                git('init')
                old = {'name': 'previous friendly name', 'type': 'http', 'server': '8.8.8.8', 'port': 443,
                       'username': 'fixture', 'password': 'old-credential'}
                raw = a.s.canonical_node(old)
                old_id = 'n-' + hashlib.sha256(json.dumps(raw, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:12]
                a.s.dump(Path('优选配置.yaml'), {'proxies': [old]})
                Path('连通性报告.json').write_text(json.dumps({'published_node_ids': [old_id],
                    'nodes': [{'id': old_id, 'name': old['name'], 'sources': ['upstream'],
                               'download': {'status': 'passed'}, 'app_tls': {'status': 'passed'}}]}))
                git('add', '优选配置.yaml', '连通性报告.json')
                git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'previous publication')
                a.s.dump(Path('聚合配置.yaml'), {})
                new = {'name': 'n-current', 'type': 'http', 'server': '1.1.1.1', 'port': 443,
                       'username': 'fixture', 'password': 'new-credential'}
                with patch.object(sys, 'argv', ['availability', '--phase', 'prepare', '--mihomo', 'unused']), \
                     patch.object(a.s, 'load_sources', return_value={}), \
                     patch.object(a.s, 'collect', return_value=([new], {}, [])), \
                     patch.object(a.s.Core, 'validate_nodes', lambda self: (self.config['proxies'], [])), \
                     patch.object(a, 'service_status', return_value={}):
                    a.main()
                bundle = json.loads(Path('.node-work/availability/bundle.json').read_text())
                nodes = {n['name']: n for n in bundle['nodes']}
                self.assertEqual(set(nodes), {'n-current', old_id})
                self.assertEqual(nodes[old_id]['password'], 'old-credential')
                self.assertNotIn('download', nodes[old_id])
                self.assertNotIn('app_tls', nodes[old_id])
                self.assertEqual(bundle['historical_candidates']['added_count'], 1)
            finally:
                os.chdir(cwd)
