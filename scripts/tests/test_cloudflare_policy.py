import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a
from medium_speed_fixture import verified_medium
import mobile_pilot as pilot
from tls_fixture import verified_tls


def challenge(label='Reddit'):
    return pilot.classify_response(label, 403, pilot.SITES[label],
        {'cf-mitigated': 'challenge', 'content-type': 'text/html'}, b'<title>Just a moment...</title>')


def summarize(label, attempts):
    return a.summarize_rounds([{label: item} for item in attempts], (label,))[label]


class CloudflarePolicyTests(unittest.TestCase):
    def setUp(self):
        medium = patch.object(a, 'medium_speed_download', side_effect=lambda port: verified_medium())
        medium.start(); self.addCleanup(medium.stop)

    def record(self):
        return {'app_tls': verified_tls(), 'websites': {
            **{label: {'status': 'passed', 'passed_count': 3, 'round_count': 3,
                      'median_elapsed_ms': 100, 'p95_elapsed_ms': 120, 'jitter_ms': 20}
               for label in a.OVERSEAS_SITES},
            'ClaudeTrace': {'status': 'passed', 'passed_count': 1, 'round_count': 1}}}

    def test_access_exception_does_not_invent_normal_page_success_or_speed(self):
        item = summarize('Reddit', [challenge()] * 3)
        self.assertEqual(item['status'], 'verification_required')
        self.assertEqual((item['accepted_count'], item['passed_count']), (3, 0))
        self.assertIsNone(item['median_elapsed_ms'])
        good = self.record()
        good['websites']['Reddit'] = item
        self.assertTrue(a.required_websites_passed(good))
        self.assertTrue(a.web_quality_eligible(good))
        self.assertEqual(a.website_count(good), len(a.OVERSEAS_SITES) - 1)
        self.assertEqual(a.website_access_count(good), len(a.OVERSEAS_SITES))
        # All optional pages may be challenges: access coverage still qualifies,
        # while real Google/YouTube response quality remains available for ranking.
        for label in a.OVERSEAS_SITES:
            if label not in a.CORE_SITES:
                good['websites'][label] = summarize(label, [challenge(label)] * 3)
        self.assertTrue(a.web_quality_eligible(good))
        self.assertEqual(a.website_count(good), 2)
        self.assertEqual(a.web_rank_metrics(good), (120, 100, 20, 120, 100, 20))

    def test_timeout_generic_403_and_missing_challenge_evidence_still_block(self):
        for last in ({'status': 'failed', 'reason': 'timeout'},
                     {'status': 'needs_review', 'http_status': 403},
                     {**challenge(), 'cf_mitigated': ''}):
            good = self.record()
            good['websites']['Reddit'] = summarize('Reddit', [challenge(), challenge(), last])
            self.assertFalse(a.required_websites_passed(good), last)
        good = self.record()
        good['websites']['Google'] = summarize('Google', [challenge('Google')] * 3)
        self.assertTrue(a.required_websites_passed(good))
        self.assertFalse(a.web_quality_eligible(good))  # No real-page timing evidence.

    def test_expected_https_host_and_header_required_trace_never_exempt(self):
        for label, url, headers in (
            ('Reddit', 'https://unexpected.example/', {'cf-mitigated': 'challenge'}),
            ('Reddit', pilot.SITES['Reddit'].replace('https:', 'http:'), {'cf-mitigated': 'challenge'}),
            ('Reddit', pilot.SITES['Reddit'], {'server': 'cloudflare'}),
            ('ClaudeTrace', pilot.SITES['ClaudeTrace'], {'cf-mitigated': 'challenge'}),
            ('Google204', pilot.SITES['Google204'], {'cf-mitigated': 'challenge'})):
            item = pilot.classify_response(label, 403, url, headers, b'Just a moment Cloudflare')
            self.assertNotEqual(item['status'], 'verification_required', (label, url, headers))
            self.assertNotEqual(item['status'], 'passed')

    def test_real_pipeline_continues_tls_and_download_then_merge_validates_evidence(self):
        pages = {label: {'status': 'passed', 'elapsed_ms': 100} for label in a.POST_SITES}
        pages['Reddit'] = {**challenge(), 'elapsed_ms': 40, 'ttfb_ms': 30}
        node = {'name': 'n-a', 'type': 'ss', 'server': '8.8.8.8', 'port': 443}
        pre = summarize('Google204', [{'status': 'passed', 'elapsed_ms': 10}] * 3)
        calls = []
        with patch.object(a.s, 'Core'), patch.object(a.s, 'query_exit', return_value=None), \
             patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1234})), \
             patch.object(a.app_tls, 'check', return_value=verified_tls()) as tls:
            rows, _ = a.probe_pipeline([node], 'unused', Path('.'), precheck=lambda port: pre,
                probe=lambda key, pace: {'status': 'passed'}, site_check=lambda port: pages,
                download=lambda port: calls.append(port) or {'status': 'failed'})
        self.assertEqual(calls, [1234])
        tls.assert_called_once_with(1234)
        bundle = {'id': 'batch', 'nodes': [node]}
        part = {'bundle_id': 'batch', 'index': 0, 'count': 1, 'endpoint_count': 1, 'records': rows}
        a.merge_shards(bundle, [part], 1)
        rows[0]['websites']['Reddit']['attempts'][0].pop('cf_mitigated')
        with self.assertRaisesRegex(ValueError, 'Cloudflare'):
            a.merge_shards(bundle, [part], 1)

    def test_repair_reclassifies_captured_flags_without_new_measurements(self):
        explicit = challenge()
        explicit.pop('cf_mitigated')
        explicit.update(status='needs_review', elapsed_ms=70, ttfb_ms=50)
        record = {'websites_updated_at': 'original-time', 'download': {'status': 'passed'},
            'websites': {'Reddit': summarize('Reddit', [copy.deepcopy(explicit) for _ in range(3)]),
                'ClaudeTrace': summarize('ClaudeTrace', [copy.deepcopy(explicit)])}}
        before = copy.deepcopy(record)
        self.assertEqual(a.reclassify_cloudflare_records([record]), 3)
        self.assertEqual(record['websites_updated_at'], 'original-time')
        self.assertEqual(record['download'], before['download'])
        self.assertEqual(record['websites']['ClaudeTrace'], before['websites']['ClaudeTrace'])
        self.assertEqual(record['websites']['Reddit']['status'], 'verification_required')
        for item in record['websites']['Reddit']['attempts']:
            self.assertEqual((item['http_status'], item['elapsed_ms'], item['ttfb_ms']), (403, 70, 50))
        self.assertEqual(a.reclassify_cloudflare_records([record]), 0)  # Idempotent.
