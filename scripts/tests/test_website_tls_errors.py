from pathlib import Path
import ssl
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mobile_pilot as p

class WebsiteTLSErrors(unittest.TestCase):
    def test_nested_proxy_tls_errors_are_detected_without_publishing_message(self):
        inner=p.s.requests.exceptions.SSLError('TLS EOF PRIVATE')
        outer=p.s.requests.exceptions.ProxyError(inner)
        self.assertEqual(p.tls_failure_kind(outer),'tls_handshake_or_transport_failed')
        self.assertEqual(p.tls_failure_kind(p.s.requests.exceptions.SSLError('CERTIFICATE_VERIFY_FAILED')),
                         'certificate_verification_failed')
        self.assertIsNone(p.tls_failure_kind(p.s.requests.exceptions.ReadTimeout('timeout')))
        self.assertIsNone(p.tls_failure_kind(p.s.requests.exceptions.ProxyError('connection refused')))
