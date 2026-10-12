from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import compare_204 as d

class Compare204Tests(unittest.TestCase):
    def test_tcp_passed_includes_later_failed_and_rejects_missing_source(self):
        bundle={'nodes':[{'name':'a'}, {'name':'b'}, {'name':'c'}]}
        report={'nodes':[{'id':'a','entry':{'status':'passed'},'websites':{'status':'failed'}},
                         {'id':'b','entry':{'status':'failed'}}, {'id':'c','entry':{'status':'passed'}}]}
        self.assertEqual([n['name'] for n in d.candidates(bundle,report)],['a','c'])
        with self.assertRaises(ValueError): d.candidates({'nodes':[]},report)

    def test_all_rounds_required_and_order_alternates(self):
        calls=[]
        def probe(port,url):
            calls.append(url)
            return {'status':'failed' if len(calls)==4 else 'passed','elapsed_ms':100}
        with patch.object(d,'probe',side_effect=probe): result=d.inspect(123)
        g,c=d.URLS.values()
        self.assertEqual(calls,[g,c,c,g,g,c])
        self.assertFalse(result['Google']['passed'])
        self.assertTrue(result['Cloudflare']['passed'])
        self.assertEqual(d.category(result),'cloudflare_only')
