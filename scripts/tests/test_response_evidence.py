from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import mobile_pilot as p

class ResponseEvidenceTests(unittest.TestCase):
    def test_redirect_target_and_chain_are_retained_without_query_or_credentials(self):
        item=p.classify_response('Gemini',302,p.SITES['Gemini'],
            {'Location':'https://accounts.google.com/ServiceLogin?continue=private','Set-Cookie':'secret'},b'')
        self.assertEqual(item.get('redirect_target'),'https://accounts.google.com/ServiceLogin')
        self.assertNotIn('private',str(item)); self.assertNotIn('secret',str(item))
    def test_network_security_denial_is_not_cf_challenge_or_generic_redirect(self):
        item=p.classify_response('Reddit',403,p.SITES['Reddit'],{'server':'cloudflare'},
            b'<html>You have been blocked by network security.</html>')
        self.assertEqual(item.get('restriction'),'reddit_network_security')
        self.assertEqual(item['status'],'needs_review')
        self.assertFalse(p.confirmed_cloudflare_challenge('Reddit',item))
    def test_empty_403_is_explicitly_unknown_denial_not_region_block(self):
        item=p.classify_response('TikTok',403,p.SITES['TikTok'],{},b'')
        self.assertEqual(item.get('restriction'),'http_access_denied')
        self.assertEqual(item['status'],'needs_review')
    def test_ordinary_page_script_mentions_do_not_create_restriction(self):
        item=p.classify_response('Reddit',200,p.SITES['Reddit'],{'content-type':'text/html'},
            b'<html>Reddit<script>const help="blocked by network security";</script></html>')
        self.assertEqual(item['status'],'passed')
        self.assertNotIn('restriction',item)

if __name__=='__main__': unittest.main()

class BrowserProfileTests(unittest.TestCase):
    def test_public_pages_use_browser_compatible_user_agent(self):
        self.assertIn('Mozilla/5.0',p.WEB_USER_AGENT)
    def test_gemini_sorry_redirect_must_return_to_real_gemini_page(self):
        from unittest.mock import patch
        class Response:
            headers={'content-type':'text/html'}
            def __init__(self,status,url,target=None):
                self.status_code=status;self.url=url
                self.headers={**self.headers,**({'Location':target} if target else {})}
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def iter_content(self,size):return iter([b'<html>Gemini Sign in</html>'])
        chain=[Response(302,p.SITES['Gemini'],'https://www.google.com/sorry/index?continue=secret'),
               Response(302,'https://www.google.com/sorry/index?continue=secret',p.SITES['Gemini']),
               Response(200,p.SITES['Gemini'])]
        with patch.object(p.s,'session') as session:
            session.return_value.__enter__.return_value.get.side_effect=chain
            item=p.check_site(1234,'Gemini',p.SITES['Gemini'])
        self.assertEqual(item['status'],'passed')
        self.assertEqual(len(item['redirect_chain']),2)
        self.assertNotIn('secret',str(item))
    def test_sorry_page_itself_unrelated_hosts_and_http_are_never_accepted(self):
        from unittest.mock import patch
        class Response:
            status_code=302;url=p.SITES['Gemini']
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def iter_content(self,size):return iter([b'<html>Gemini</html>'])
        for target in ('http://www.google.com/sorry/index','https://evil.example/sorry/index',
                       'https://www.google.com/unrelated'):
            with self.subTest(target=target),patch.object(p.s,'session') as session:
                response=Response();response.headers={'Location':target,'content-type':'text/html'}
                session.return_value.__enter__.return_value.get.return_value=response
                item=p.check_site(1234,'Gemini',p.SITES['Gemini'])
                self.assertEqual(item['status'],'needs_review')
                self.assertEqual(session.return_value.__enter__.return_value.get.call_count,1)
        item=p.classify_response('Gemini',200,'https://www.google.com/sorry/index',
                                {'content-type':'text/html'},b'<html>Gemini unusual traffic</html>')
        self.assertEqual(item['status'],'needs_review')
