import copy
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import availability as a
import detection_report as d
import service_probes as p
from test_medium_speed import record
from tls_fixture import verified_tls
from upload_fixture import verified_upload_precheck
from medium_speed_fixture import verified_medium
from high_speed_fixture import verified_high


class Response:
    def __init__(self, url, body, status=200, content_type='application/json', headers=None):
        self.url, self.body, self.status_code = url, body, status
        self.headers = {'Content-Type': content_type, **(headers or {})}
        self.raw = io.BytesIO(body)

    def __enter__(self): return self
    def __exit__(self, *args): pass
    def iter_content(self, size):
        return (self.body[i:i+size] for i in range(0, len(self.body), size))


def api_result(url=p.CHATGPT_API):
    return {'status': 'response_received', 'url': url, 'content_type': 'application/json',
            'http_status': 200, 'elapsed_ms': 100, 'reason': '等待内容校验'}


def checks(status='unknown'):
    return {'version': p.VERSION, 'targets': {label: {'status': status} for label in p.TARGETS}}


class ServiceProbeTests(unittest.TestCase):
    def test_chatgpt_requires_expected_boolean_json_not_absence_of_denial(self):
        for data, status in (({'cookie_consent_required': False}, 'passed'),
                ({'cookie_consent_required': True}, 'passed'), ({}, 'unknown'),
                ({'cookie_consent_required': 'false'}, 'unknown'),
                ({'error': {'code': 'server_error'}}, 'unknown'),
                ({'error': {'code': 'unsupported_country'}}, 'restricted')):
            with self.subTest(data=data), patch.object(p, 'fetch', return_value=(api_result(), json.dumps(data).encode())):
                self.assertEqual(p.chatgpt_api(1)['status'], status)
        with patch.object(p, 'fetch', return_value=(api_result(), b'<html>Fine</html>')):
            self.assertEqual(p.chatgpt_api(1)['status'], 'unknown')

    def test_http_404_or_cf_wall_never_counts_as_api_success(self):
        for status in ('unavailable', 'verification_required', 'restricted'):
            with patch.object(p, 'fetch', return_value=({**api_result(), 'status': status}, b'{"cookie_consent_required":false}')):
                self.assertEqual(p.chatgpt_api(1)['status'], status)

    def test_trace_requires_ip_host_scheme_and_plain_text(self):
        valid = b'h=www.tiktok.com\nip=8.8.8.8\nvisit_scheme=https\nloc=US\ncolo=LAX\n'
        result = {**api_result(p.TIKTOK_TRACE), 'content_type': 'text/plain'}
        for body, status in ((valid, 'passed'), (valid.replace(b'8.8.8.8', b'127.0.0.1'), 'unavailable'),
                (valid.replace(b'www.tiktok.com', b'evil.example'), 'unavailable'),
                (valid.replace(b'loc=US', b'loc=us'), 'unavailable'),
                (valid.replace(b'https', b'http'), 'unavailable'), (b'<html>TikTok</html>', 'unavailable')):
            with self.subTest(body=body), patch.object(p, 'fetch', return_value=(result, body)):
                self.assertEqual(p.tiktok_trace(1)['status'], status)
        with patch.object(p, 'fetch', return_value=({**result, 'content_type': 'text/html'}, valid)):
            self.assertEqual(p.tiktok_trace(1)['status'], 'unavailable')

    def test_fast_target_is_restricted_and_uses_exact_1mb_range(self):
        original = 'https://ipv4-c001.example.nflxvideo.net/speedtest/range/0-0?o=PRIVATE_SIGNED_QUERY'
        target = p.fast_target({'targets': [{'url': original, 'location': {'country': 'US'}}]})
        self.assertEqual(target, (original.replace('0-0?', '0-999999?'), 'US'))
        for bad in ('http://example.nflxvideo.net/speedtest/range/0-0',
                'https://127.0.0.1/speedtest/range/0-0', 'https://nflxvideo.net.evil.com/speedtest/range/0-0',
                'https://x.nflxvideo.net@evil.com/speedtest/range/0-0',
                'https://x.nflxvideo.net:444/speedtest/range/0-0',
                'https://x.nflxvideo.net/something', 'https://x.nflxvideo.net:bad/speedtest/range/0-0'):
            with self.subTest(url=bad):
                self.assertIsNone(p.fast_target({'targets': [{'url': bad}]}))
        self.assertIsNone(p.fast_target({'targets': []}))

    def test_fetch_retains_tls_verification_and_redacts_body_query_and_cookies(self):
        body = b'{"cookie_consent_required":false}'
        response = Response(p.FAST_API, body, headers={'Set-Cookie': 'PRIVATE_COOKIE'})
        with patch.object(p.s, 'session') as session:
            client = session.return_value.__enter__.return_value
            client.get.return_value = response
            result, raw = p.fetch(1234, p.FAST_API)
            self.assertTrue(client.get.call_args.kwargs['verify'])
            self.assertFalse(client.get.call_args.kwargs['allow_redirects'])
            self.assertEqual(client.proxies['https'], 'http://127.0.0.1:1234')
        self.assertEqual(raw, body)
        self.assertNotIn('token=', json.dumps(result))
        self.assertNotIn('PRIVATE_COOKIE', json.dumps(result))
        self.assertNotIn('cookie_consent_required', json.dumps(result))

    def test_fetch_bounds_body_and_identifies_certificate_error(self):
        with patch.object(p.s, 'session') as session:
            client = session.return_value.__enter__.return_value
            client.get.return_value = Response(p.CHATGPT_API, b'x' * (p.BODY_LIMIT + 100))
            result, body = p.fetch(None, p.CHATGPT_API)
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(len(body), p.BODY_LIMIT + 1)
            client.get.side_effect = p.s.requests.exceptions.SSLError('CERTIFICATE_VERIFY_FAILED')
            result, _ = p.fetch(None, p.CHATGPT_API)
            self.assertEqual(result['tls_error_kind'], 'certificate_verification_failed')

    def test_fast_api_success_alone_does_not_claim_bandwidth_or_unlock(self):
        body = json.dumps({'targets': [{'url': 'https://a.nflxvideo.net/speedtest/range/0-0?o=PRIVATE'}]}).encode()
        with patch.object(p, 'fetch', return_value=(api_result(), body)), \
                patch.object(p, 'fast_download', return_value={'status': 'failed', 'reason': 'partial'}) as download:
            result = p.fast(1)
        self.assertEqual(result['api']['status'], 'passed')
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertTrue(download.call_args.args[1].endswith('0-999999?o=PRIVATE'))
        with patch.object(p, 'fetch', return_value=({'status': 'restricted', 'reason': '403'}, b'')), \
                patch.object(p, 'fast_download') as download:
            p.fast(1)
            download.assert_not_called()

    def test_fast_download_requires_complete_correct_file(self):
        url = 'https://a.nflxvideo.net/speedtest/range/0-999999?o=PRIVATE'
        for length, body_bytes, status in ((p.DOWNLOAD_BYTES, p.DOWNLOAD_BYTES, 'passed'),
                                          (p.DOWNLOAD_BYTES, 100, 'failed'), (100, 100, 'failed')):
            response = Response(url, b'x' * body_bytes, content_type='application/octet-stream',
                                headers={'Content-Length': str(length)})
            with patch.object(p.s, 'session') as session:
                client = session.return_value.__enter__.return_value
                client.get.return_value = response
                result = p.fast_download(1, url)
                self.assertTrue(client.get.call_args.kwargs['verify'])
            self.assertEqual(result['status'], status)
            self.assertNotIn('PRIVATE', json.dumps(result))

    def test_optional_restrictions_do_not_remove_nodes_but_certificate_errors_do(self):
        row = record()
        row['service_checks'] = checks('restricted')
        self.assertTrue(a.web_quality_eligible(row))
        self.assertFalse(a.destination_certificate_failure(row))
        for label, component in (('ChatGPTAPI', None), ('TikTokTrace', None), ('FAST', 'api'), ('FAST', 'download')):
            broken = copy.deepcopy(row)
            item = broken['service_checks']['targets'][label]
            if component:
                item[component] = {}; item = item[component]
            item['tls_error_kind'] = 'certificate_verification_failed'
            self.assertTrue(a.destination_certificate_failure(broken))
            self.assertFalse(a.web_quality_eligible(broken))

    def test_summary_distinguishes_api_success_from_unmeasured_cdn(self):
        value = checks()
        value['targets']['FAST'] = {'status': 'restricted', 'api': {'status': 'restricted'}}
        summary = p.summary([{'service_checks': value}, {}])
        self.assertEqual(summary['FAST']['measured'], 0)
        self.assertEqual(summary['FASTAPI']['restricted'], 1)
        self.assertEqual(summary['FASTAPI']['unmeasured'], 1)
        text = '\n'.join(d.service_checks_table([{'service_checks': value}]))
        self.assertIn('FAST测速API', text)
        self.assertIn('普通接口异常不淘汰', text)

    def test_pipeline_runs_supplement_after_quick_download_and_preserves_coverage(self):
        node = {'name': 'n-service', 'type': 'ss', 'server': '8.8.8.8', 'port': 443}
        pre = a.summarize_rounds([{'Google204': {'status': 'passed', 'elapsed_ms': 10}}] * 3, ('Google204',))['Google204']
        pages = {label: {'status': 'passed', 'elapsed_ms': 100} for label in a.POST_SITES}
        calls = []
        with patch.object(a.s, 'Core'), patch.object(a.s, 'query_exit', return_value=None), \
                patch.object(a.s, 'make_listeners', return_value=([], {'n-service': 1234})), \
                patch.object(a.app_tls, 'check', return_value=verified_tls()):
            rows, _ = a.probe_pipeline([node], 'unused', Path('.'), precheck=lambda port: pre,
                probe=lambda key, pace: {'status': 'passed'}, site_check=lambda port: pages,
                download=lambda port: calls.append('1MB') or {'status': 'passed', 'received_bytes': 1000000, 'elapsed_ms': 100},
                medium_download=lambda port: verified_medium(5), large_download=lambda port: verified_high(10),
                upload_precheck=verified_upload_precheck,
                service_check=lambda port, gate: calls.append('services') or checks('restricted'))
        self.assertEqual(calls, ['1MB', 'services'])
        self.assertEqual(set(rows[0]['websites']), set(a.DAILY_POST_SITES))
        bundle = {'id': 'batch', 'nodes': [node], 'service_checks_enabled': True}
        part = {'bundle_id': 'batch', 'index': 0, 'count': 1, 'endpoint_count': 1, 'records': rows}
        a.merge_shards(bundle, [part], 1)
        rows[0].pop('service_checks')
        with self.assertRaisesRegex(ValueError, '补充服务'):
            a.merge_shards(bundle, [part], 1)


if __name__ == '__main__':
    unittest.main()
