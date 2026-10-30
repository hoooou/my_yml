import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import mobile_pilot as p
import availability as a
import detection_report as d
from test_cloudflare_policy import challenge


def prompt():
    return p.classify_response('Reddit',403,p.SITES['Reddit'],{'content-type':'text/html','server':'snooserv'},
        b'<html><style>ignored</style><h1>You have been blocked by network security.</h1>'
        b'<p>To continue, <a href="/login/">Log in</a> to your Reddit account.</p></html>')

class RedditLoginPolicyTests(unittest.TestCase):
    def test_explicit_login_prompt_counts_as_access_without_inventing_page_speed(self):
        item=prompt()
        self.assertEqual(item['status'],'login_required')
        self.assertEqual(item['http_status'],403)
        self.assertTrue(p.confirmed_reddit_login('Reddit',item))
        summary=a.summarize_rounds([{'Reddit':item}]*3,('Reddit',))['Reddit']
        self.assertTrue(a.page_rounds_accepted('Reddit',summary))
        self.assertEqual(summary['accepted_count'],3)
        self.assertEqual(summary['passed_count'],0)
        self.assertIsNone(summary['median_elapsed_ms'])
        self.assertEqual(summary['login_required_count'],3)
        counts=d.website_access_summary([{'websites':{'Reddit':summary}}])['Reddit']
        self.assertEqual(counts['accepted'],1)
        self.assertEqual(counts['login_required'],1)
        self.assertEqual(counts['restricted'],0)
    def test_mixed_normal_cf_login_rounds_accepted_but_timeout_or_plain403_not_hidden(self):
        normal={'status':'passed','http_status':200,'elapsed_ms':100}
        rounds=[prompt(),challenge(),normal]
        item=a.summarize_rounds([{'Reddit':r} for r in rounds],('Reddit',))['Reddit']
        self.assertTrue(a.page_rounds_accepted('Reddit',item))
        for bad in ({'status':'failed','error_type':'ReadTimeout'},
                    {'status':'needs_review','http_status':403},
                    {**prompt(),'login_prompt_signals':{}}):
            item=a.summarize_rounds([{'Reddit':r} for r in [prompt(),normal,bad]],('Reddit',))['Reddit']
            self.assertFalse(a.page_rounds_accepted('Reddit',item))
    def test_server_name_generic_login_mentions_wrong_host_and_other_sites_not_exempt(self):
        for label,url,body in [('Reddit',p.SITES['Reddit'],b'Access denied'),
                              ('Reddit',p.SITES['Reddit'],b'<script>"blocked by network security log in"</script>'),
                              ('Reddit','https://unrelated.example/',b'blocked by network security log in'),
                              ('Reddit','http://www.reddit.com/',b'blocked by network security log in'),
                              ('Gemini',p.SITES['Gemini'],b'blocked by network security log in')]:
            item=p.classify_response(label,403,url,{'server':'snooserv','content-type':'text/html'},body)
            self.assertNotEqual(item['status'],'login_required')
    def test_real_pipeline_continues_tls_download_and_merge_rejects_forged_login(self):
        from upload_fixture import verified_upload_precheck
        from tls_fixture import verified_tls
        from medium_speed_fixture import verified_medium
        from high_speed_fixture import verified_high
        node={'name':'n-login','type':'ss','server':'8.8.8.8','port':443}
        pre=a.summarize_rounds([{'Google204':{'status':'passed','elapsed_ms':10}}]*3,('Google204',))['Google204']
        pages={label:{'status':'passed','elapsed_ms':100} for label in a.POST_SITES}
        pages['Reddit']={**prompt(),'elapsed_ms':80,'ttfb_ms':70}
        calls=[]
        with patch.object(a.s,'Core'), patch.object(a.s,'query_exit',return_value=None), \
             patch.object(a.s,'make_listeners',return_value=([],{'n-login':1234})), \
             patch.object(a.app_tls,'check',return_value=verified_tls()) as tls:
            rows,_=a.probe_pipeline([node],'unused',Path('.'),precheck=lambda port:pre,
                probe=lambda key,pace:{'status':'passed'},site_check=lambda port:pages,
                download=lambda port:calls.append(port) or {'status':'passed','received_bytes':a.DOWNLOAD_BYTES,'elapsed_ms':100},
                medium_download=lambda port:verified_medium(),
                large_download=lambda port:verified_high(),
                upload_precheck=verified_upload_precheck)
        self.assertEqual(calls,[1234]);tls.assert_called_once_with(1234)
        bundle={'id':'batch','nodes':[node]}
        part={'bundle_id':'batch','index':0,'count':1,'endpoint_count':1,'records':rows}
        a.merge_shards(bundle,[part],1)
        rows[0]['websites']['Reddit']['attempts'][0].pop('login_prompt_signals')
        with self.assertRaisesRegex(ValueError,'Reddit'):
            a.merge_shards(bundle,[part],1)

    def test_sample_can_find_login_text_after_large_css_prefix(self):
        body=b'<style>'+b'x'*180000+b'</style><h1>blocked by network security</h1><a href="/login/">Log in</a>'
        class Response:
            status_code=403;url=p.SITES['Reddit'];headers={'content-type':'text/html','server':'snooserv'}
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def iter_content(self,size):return (body[i:i+size] for i in range(0,len(body),size))
        with patch.object(p.s,'session') as session:
            session.return_value.__enter__.return_value.get.return_value=Response()
            result=p.check_site(1234,'Reddit',p.SITES['Reddit'])
        self.assertEqual(result['status'],'login_required')
        self.assertGreater(result['sample_bytes'],16384)
        self.assertNotIn('x'*100,str(result))

if __name__=='__main__':unittest.main()
