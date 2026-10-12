import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import website_diagnostics as d
import mobile_pilot as p

class WebsiteDiagnosticTests(unittest.TestCase):
    def test_meta_http400_failures_are_selected_for_diagnosis_not_silently_skipped(self):
        rows = [{'id': str(i), 'exit': {'exit_ip': str(i)}, 'websites': {
            label: {'status': 'failed', 'attempts': [{'status': 'failed', 'http_status': 400}] * 3}
            for label in ('Facebook', 'WhatsApp')}} for i in range(3)]
        tasks = d.choose_samples({'nodes': [{'name': str(i)} for i in range(3)]},
                                 {'nodes': rows}, limit=2, labels=('Facebook', 'WhatsApp'))
        self.assertEqual(len(tasks), 4)
        self.assertEqual({t['group'] for t in tasks}, {'http_error'})

    def test_evidence_omits_cookies_and_query_retains_denial_signal(self):
        item = d.evidence('Reddit',403,p.SITES['Reddit'],
            {'Location':'https://accounts.google.com/login?secret=do-not-publish','Set-Cookie':'secret'},
            b'<title>Blocked</title>You have been blocked by network security.')
        self.assertTrue(item['denial_signals']['blocked by network security'])
        self.assertEqual(item['headers']['location'], 'https://accounts.google.com/login')
        self.assertNotIn('secret', str(item))
    def test_sample_covers_all_restricted_categories_and_passed_controls(self):
        rows = [{'id':str(i), 'websites':{'Gemini':{'status':status,'attempts':
            [{'status':status,'http_status':code}]}}} for i,(status,code) in enumerate(
            [('needs_review',302),('needs_review',403),('passed',200)])]
        tasks = d.choose_samples({'nodes':[{'name':str(i)} for i in range(3)]}, {'nodes':rows})
        self.assertEqual({t['group'] for t in tasks}, {'redirect','denied','passed'})
    def test_cf_challenge_accepted_on_every_page_site(self):
        for label in p.PAGE_SITES:
            item = p.classify_response(label,403,p.SITES[label],{'cf-mitigated':'challenge'},b'Just a moment')
            self.assertEqual(item['status'],'verification_required',label)
            self.assertTrue(p.confirmed_cloudflare_challenge(label,item),label)

if __name__ == '__main__':
    unittest.main()
