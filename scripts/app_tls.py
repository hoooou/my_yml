"""Fresh, verified TLS handshakes through a node's isolated HTTP listener."""
import concurrent.futures as futures
import hashlib
import math
import re
import socket
import ssl
import time

import certifi

TARGETS = ('chatgpt.com', 'android.chat.openai.com', 'auth.openai.com', 'cdn.oaistatic.com')
ROUNDS = 2
BUDGET_SECONDS = 5
VERSION = 1


def probe(port, hostname, context=None):
    if hostname not in TARGETS:
        raise ValueError('Unknown application TLS target')
    started = time.monotonic()
    deadline = started + BUDGET_SECONDS
    result = {'hostname': hostname, 'status': 'failed', 'phase': 'connect',
              'chain_verified': False, 'hostname_verified': False, 'validity_verified': False}
    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError('TLS probe budget exceeded')
        return value
    try:
        context = context or ssl.create_default_context(cafile=certifi.where())
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError('TLS verification must remain enabled')
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        address = ('127.0.0.1', port) if port is not None else (hostname, 443)
        with socket.create_connection(address, timeout=remaining()) as raw:
            if port is not None:
                result['phase'] = 'proxy_connect'
                raw.settimeout(remaining())
                raw.sendall((f'CONNECT {hostname}:443 HTTP/1.1\r\n'
                             f'Host: {hostname}:443\r\n\r\n').encode('ascii'))
                headers = bytearray()
                while not headers.endswith(b'\r\n\r\n'):
                    if len(headers) >= 8192:
                        raise ValueError('Proxy CONNECT headers exceeded budget')
                    raw.settimeout(remaining())
                    byte = raw.recv(1)
                    if not byte:
                        raise OSError('Proxy CONNECT closed')
                    headers.extend(byte)
                if not re.fullmatch(rb'HTTP/1\.[01] 200(?: [^\r\n]*)?', bytes(headers).split(b'\r\n', 1)[0]):
                    raise OSError('Proxy CONNECT refused')
            result['phase'] = 'tls_handshake'
            raw.settimeout(remaining())
            with context.wrap_socket(raw, server_hostname=hostname) as secured:
                remaining()
                cert = secured.getpeercert()
                now = time.time()
                if not (ssl.cert_time_to_seconds(cert['notBefore']) <= now <
                        ssl.cert_time_to_seconds(cert['notAfter'])):
                    raise ValueError('Certificate validity interval failed')
                result.update(status='passed', phase='complete', chain_verified=True,
                    hostname_verified=True, validity_verified=True, tls_version=secured.version(),
                    certificate_sha256=hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest(),
                    issuer={key: value for item in cert.get('issuer', ()) for key, value in item
                            if key in ('commonName', 'organizationName')},
                    not_before=cert['notBefore'], not_after=cert['notAfter'])
    except ssl.SSLCertVerificationError as error:
        result.update(error_type='certificate_verification_failed',
                      verify_code=error.verify_code, verify_message=error.verify_message)
    except (socket.timeout, TimeoutError):
        result['error_type'] = 'timeout'
    except ssl.SSLError:
        result['error_type'] = 'tls_handshake_failed'
    except (OSError, ValueError, KeyError):
        result['error_type'] = 'connection_or_protocol_failed'
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000, 1)
    if result['elapsed_ms'] > BUDGET_SECONDS * 1000:
        result.update(status='failed', error_type='timeout')
    return result


def check(port, retry_transient=False):
    def measure(hostname):
        attempts = [probe(port, hostname) for _ in range(ROUNDS)]
        if retry_transient and sum(r['status'] == 'passed' for r in attempts) == 1 and any(
                r.get('error_type') in ('timeout', 'connection_or_protocol_failed') for r in attempts):
            attempts.append(probe(port, hostname))
        accepted = sum(r['status'] == 'passed' for r in attempts) >= ROUNDS and all(
            r['status'] == 'passed' or r.get('error_type') in ('timeout', 'connection_or_protocol_failed') for r in attempts)
        return hostname, {'status': 'passed' if accepted else 'failed',
                          'round_count': len(attempts), 'attempts': attempts}
    with futures.ThreadPoolExecutor(max_workers=2) as pool:
        targets = dict(pool.map(measure, TARGETS))
    result = {'version': 2 if retry_transient else VERSION, 'status': 'passed' if all(r['status'] == 'passed' for r in targets.values())
              else 'failed', 'targets': targets}
    return result


def passed(result):
    """Fail closed on old/missing, mismatched, unverified or incomplete evidence."""
    if (not isinstance(result, dict) or result.get('version') not in (VERSION, 2) or result.get('status') != 'passed'
            or set(result.get('targets') or {}) != set(TARGETS)):
        return False
    for hostname, item in result['targets'].items():
        attempts = item.get('attempts') or []
        if (item.get('status') != 'passed' or item.get('round_count') != len(attempts)
                or len(attempts) not in ((2, 3) if result['version'] == 2 else (2,))
                or sum(a.get('status') == 'passed' for a in attempts) < ROUNDS):
            return False
        for attempt in attempts:
            if (result['version'] == 2 and attempt.get('status') == 'failed'
                    and attempt.get('hostname') == hostname
                    and attempt.get('error_type') in ('timeout', 'connection_or_protocol_failed')):
                continue
            elapsed = attempt.get('elapsed_ms')
            if (attempt.get('status') != 'passed' or attempt.get('hostname') != hostname
                    or any(attempt.get(k) is not True for k in
                           ('chain_verified', 'hostname_verified', 'validity_verified'))
                    or type(elapsed) not in (int, float) or not math.isfinite(elapsed)
                    or not 0 <= elapsed <= BUDGET_SECONDS * 1000):
                return False
    return True
