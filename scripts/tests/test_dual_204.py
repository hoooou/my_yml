import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a
import mobile_pilot as p
import latest_report

class Dual204Tests(unittest.TestCase):
    def fixture(self):
        targets={label:a.summarize_rounds([{label:{'status':'passed','elapsed_ms':10,'http_status':204,
                    'sample_bytes':0,'final_url':url}}]*3,(label,))[label] for label,url in a.PRECHECK_URLS.items()}
        node={'name':'n','type':'ss','server':'8.8.8.8','port':443}
        record={'id':'n','precheck':a.combine_204(targets),'entry':{'status':'failed'},'websites':None,
                'app_tls':{'status':'skipped'},'download':{'status':'skipped'},
                'medium_speed_download':{'status':'skipped'},'high_speed_download':{'status':'skipped'}}
        return {'id':'batch','nodes':[node],'dual_204':True}, [{'bundle_id':'batch','index':0,'count':1,'endpoint_count':1,'records':[record]}]

    def test_cloudflare_requires_exact_empty_204_not_cf_challenge(self):
        url=p.CLOUDFLARE_204_URL
        self.assertEqual(p.classify_response('Cloudflare204',204,url,{},b'')['status'],'passed')
        for status,target,body in [(200,url,b''),(204,url,b'x'),(204,url+'/other',b''),(403,url,b'Just a moment')]:
            self.assertNotEqual(p.classify_response('Cloudflare204',status,target,{},body)['status'],'passed')
        self.assertNotIn('Cloudflare204', p.POST_SITES)

    def test_merge_requires_both_original_targets_and_rejects_forged_success(self):
        bundle,parts=self.fixture()
        a.merge_shards(bundle,parts,1)
        for key in ('targets','version'):
            broken=copy.deepcopy(parts);broken[0]['records'][0]['precheck'].pop(key)
            with self.assertRaises(ValueError):a.merge_shards(bundle,broken,1)
        broken=copy.deepcopy(parts)
        broken[0]['records'][0]['precheck']['targets']['Cloudflare204']['attempts'][0]['status']='failed'
        with self.assertRaises(ValueError):a.merge_shards(bundle,broken,1)
        broken=copy.deepcopy(parts)
        broken[0]['records'][0]['precheck']['targets']['Cloudflare204']['attempts'][0]['http_status']=200
        with self.assertRaises(ValueError):a.merge_shards(bundle,broken,1)

    def test_latest_report_exposes_both_targets_and_joint_gate(self):
        bundle,parts=self.fixture()
        report={'nodes':parts[0]['records']}
        rows=latest_report.stage_summary(report)
        self.assertEqual([r['passed'] for r in rows if r['id'] in ('204','204_Google204','204_Cloudflare204')],[1,1,1])
