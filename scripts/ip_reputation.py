"""Optional keyed IP intelligence. Never infer an individual IP risk score."""
import ipaddress
import math
import re

import requests
import select_nodes as s

API_URL = 'https://api.ipapi.is/'
DAILY_LOOKUP_BUDGET = 900  # Leave headroom in the free 1,000-IP daily allowance.


def normalize(ip, value):
    if not isinstance(value, dict) or value.get('ip') != ip or value.get('error'):
        return {'status': 'unknown', 'provider': 'ipapi.is', 'reason': 'invalid_response'}
    company = value.get('company')
    if not isinstance(company, dict):
        return {'status': 'unknown', 'provider': 'ipapi.is', 'reason': 'full_response_required'}
    result = {'status': 'success', 'provider': 'ipapi.is', 'ip': ip,
              'checked_at': s.datetime.now(s.TZ).isoformat(timespec='seconds'),
              'company_type': company.get('type'),
              'asn_type': (value.get('asn') or {}).get('type') if isinstance(value.get('asn'), dict) else None}
    for field in ('is_datacenter', 'is_mobile', 'is_proxy', 'is_vpn', 'is_tor', 'is_abuser'):
        result[field] = value.get(field) if type(value.get(field)) is bool else None
    raw = company.get('abuser_score')
    match = re.fullmatch(r'\s*(\d+(?:\.\d+)?)\s*(?:\([^\n]*\))?\s*', str(raw))
    ratio = float(match.group(1)) if match else None
    result['network_abuser_ratio'] = ratio if ratio is not None and math.isfinite(ratio) and 0 <= ratio <= 1 else None
    result['network_purity_score'] = (round(100 * (1 - ratio), 2)
        if result['network_abuser_ratio'] is not None else None)
    return result


def lookup(ips, key):
    addresses = sorted({ip for ip in ips if ip and ipaddress.ip_address(ip).is_global})
    results = {ip: {'status': 'unknown', 'provider': 'ipapi.is',
                    'reason': 'not_configured' if not key else 'lookup_unavailable'} for ip in addresses}
    if not key:
        return results
    # Bulk calls count per IP. No key rotation, no anonymous fallback, no quota retries.
    selected = addresses[:DAILY_LOOKUP_BUDGET]
    with s.session() as client:
        for offset in range(0, len(selected), 100):
            batch = selected[offset:offset + 100]
            try:
                response = client.post(API_URL, json={'ips': batch, 'key': key}, timeout=20)
                if response.status_code in (401, 403, 429):
                    print('IP 信誉接口鉴权或额度不可用，停止查询；未确认字段保持未知', flush=True)
                    break
                response.raise_for_status()
                values = response.json()
                if not isinstance(values, dict):
                    continue
                for ip in batch:
                    results[ip] = normalize(ip, values.get(ip))
            except (requests.RequestException, ValueError):
                # Exceptions may include request details: never log them or credentials.
                print('IP 信誉查询批次失败，未确认字段保持未知', flush=True)
    return results


def residence_label(record):
    info = record.get('ip_reputation') or {}
    if info.get('status') == 'success':
        if info.get('is_datacenter') is True:
            return '机房'
        if info.get('is_mobile') is True:
            return '移动网络'
        if info.get('is_datacenter') is False and info.get('company_type') == 'isp':
            return '住宅候选'
    old = record.get('ip_type') or {}
    if old.get('status') == 'success':
        if old.get('hosting') is True:
            return '机房'
        if old.get('hosting') is False:
            return '非机房'
    return '住宅未知'


def purity_label(record):
    info = record.get('ip_reputation') or {}
    score = info.get('network_purity_score') if info.get('status') == 'success' else None
    text = f'网段纯净{score:.2f}' if score is not None else '纯净未知'
    return text + ('/有滥用' if info.get('is_abuser') is True else '')
