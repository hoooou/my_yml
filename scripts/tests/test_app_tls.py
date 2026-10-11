import copy
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app_tls
import availability as a
from tls_fixture import verified_tls


class AppTLSGateTests(unittest.TestCase):
    def test_failed_app_certificate_blocks_download_at_real_pipeline_caller(self):
        node = {'name': 'n-a', 'type': 'ss', 'server': '8.8.8.8', 'port': 443}
        failed = verified_tls()
        failed['status'] = 'failed'
        failed['targets']['android.chat.openai.com']['status'] = 'failed'
        failed['targets']['android.chat.openai.com']['attempts'][0].update(
            status='failed', chain_verified=False, error_type='certificate_verification_failed')
        with patch.object(a.s, 'Core'), patch.object(a.s, 'query_exit', return_value=None), \
             patch.object(a.s, 'make_listeners', return_value=([], {'n-a': 1234})), \
             patch.object(a.app_tls, 'check', return_value=failed):
            rows, _ = a.probe_pipeline([node], 'unused', Path('.'),
                precheck=lambda port: {'status': 'passed'}, probe=lambda key, pace: {'status': 'passed'},
                site_check=lambda port: {label: {'status': 'passed', 'elapsed_ms': 10} for label in a.POST_SITES},
                download=lambda port: self.fail('certificate-invalid node reached download'))
        self.assertEqual(rows[0]['app_tls']['status'], 'failed')
        self.assertEqual(rows[0]['download']['status'], 'skipped')
        self.assertFalse(a.web_quality_eligible(rows[0]))
        self.assertEqual(a.render_comparison({}, rows, {'n-a': node})['proxies'], [])

    def test_complete_verified_evidence_is_required(self):
        good = verified_tls()
        self.assertTrue(app_tls.passed(good))
        for mutate in ('missing_target', 'missing_round', 'wrong_host', 'unverified', 'timeout', 'old'):
            bad = copy.deepcopy(good)
            first = bad['targets'][app_tls.TARGETS[0]]
            if mutate == 'missing_target': bad['targets'].pop(app_tls.TARGETS[0])
            elif mutate == 'missing_round': first['attempts'].pop()
            elif mutate == 'wrong_host': first['attempts'][0]['hostname'] = 'other.test'
            elif mutate == 'unverified': first['attempts'][0]['chain_verified'] = False
            elif mutate == 'timeout': first['attempts'][0]['elapsed_ms'] = 6000
            else: bad['version'] = 0
            self.assertFalse(app_tls.passed(bad), mutate)

    def test_missing_tls_or_forged_evidence_cannot_publish_including_regional_pool(self):
        from test_required_sites import RequiredSiteTests
        record = RequiredSiteTests().record()
        self.assertTrue(a.web_quality_eligible(record))
        self.assertTrue(a.regional_eligible(record))
        for result in (None, {'status': 'passed'}, verified_tls()):
            bad = copy.deepcopy(record)
            bad['app_tls'] = result
            if result and 'targets' in result:
                result['targets'][app_tls.TARGETS[0]]['attempts'][0]['validity_verified'] = False
            self.assertFalse(a.web_quality_eligible(bad))
            self.assertFalse(a.regional_eligible(bad))


class ActualTLSValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        def openssl(*args):
            subprocess.run(['openssl', *args], cwd=cls.root, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                '-subj', '/CN=TLS test root', '-keyout', 'ca.key', '-out', 'ca.crt')
        openssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=chatgpt.com',
                '-keyout', 'server.key', '-out', 'server.csr')
        (cls.root / 'ext.cnf').write_text('subjectAltName=DNS:chatgpt.com\nbasicConstraints=CA:FALSE\n')
        openssl('x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
                '-CAcreateserial', '-days', '1', '-extfile', 'ext.cnf', '-out', 'server.crt')
        cls.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_context.load_cert_chain(str(cls.root / 'server.crt'), str(cls.root / 'server.key'))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def tunnel_probe(self, hostname, trust_test_ca):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(3)
        port = listener.getsockname()[1]
        def server():
            try:
                with listener:
                    raw, _ = listener.accept()
                    with raw:
                        raw.settimeout(3)
                        headers = b''
                        while not headers.endswith(b'\r\n\r\n'):
                            headers += raw.recv(1)
                        raw.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
                        with self.server_context.wrap_socket(raw, server_side=True):
                            pass
            except (ssl.SSLError, OSError):
                pass
        worker = threading.Thread(target=server, daemon=True); worker.start()
        context = ssl.create_default_context(cafile=str(self.root / 'ca.crt')) if trust_test_ca else None
        result = app_tls.probe(port, hostname, context)
        worker.join(3)
        return result

    def test_trusted_certificate_with_matching_hostname_passes(self):
        result = self.tunnel_probe('chatgpt.com', True)
        self.assertEqual(result['status'], 'passed', result)
        self.assertTrue(result['chain_verified'])
        self.assertTrue(result['hostname_verified'])
        self.assertTrue(result['validity_verified'])
        self.assertEqual(len(result['certificate_sha256']), 64)

    def test_unknown_issuer_is_rejected(self):
        result = self.tunnel_probe('chatgpt.com', False)
        self.assertEqual(result['error_type'], 'certificate_verification_failed', result)
        self.assertFalse(result['chain_verified'])

    def test_trusted_but_wrong_hostname_is_rejected(self):
        result = self.tunnel_probe('android.chat.openai.com', True)
        self.assertEqual(result['error_type'], 'certificate_verification_failed', result)
        self.assertFalse(result['hostname_verified'])
