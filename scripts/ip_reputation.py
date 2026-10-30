"""IP intelligence with a free fallback. Never infer an individual IP risk score."""
import ipaddress
import json
import math
import re
from pathlib import Path

import requests
import select_nodes as s

API_URL = 'https://api.ipapi.is/'
# 免费备用源：不需要 key，一次最多 100 个 IP，15 次/分钟，只提供 hosting/proxy/mobile。
FREE_URL = 'http://ip-api.com/batch'
FREE_FIELDS = 'status,message,query,hosting,proxy,mobile'
# 查过一次就存下来，7 天内同一个出口 IP 不再重复查；文件随发布一起提交。
CACHE_FILE = 'IP归属缓存.json'
CACHE_DAYS = 7
ROOT = Path(__file__).resolve().parent.parent
DAILY_LOOKUP_BUDGET = 900  # Per-run cap. Runs only look up download-passed exits (~140), so 4 runs/day stay under the free 1,000/day.


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


def cache_path():
    return ROOT / CACHE_FILE


def load_cache():
    try:
        data = json.loads(cache_path().read_text())
    except (OSError, ValueError):
        return {}
    entries = data.get('entries') if isinstance(data, dict) else None
    return entries if isinstance(entries, dict) else {}


def save_cache(entries):
    cache_path().write_text(json.dumps({'updated_at': s.datetime.now(s.TZ).isoformat(timespec='seconds'),
                                        'entries': entries}, ensure_ascii=False, indent=2, sort_keys=True) + '\n')


def cache_fresh(entry, now):
    try:
        return (now - s.datetime.fromisoformat(entry['checked_at'])).days < CACHE_DAYS
    except (KeyError, TypeError, ValueError):
        return False


def lookup(ips, key, use_cache=True):
    addresses = sorted({ip for ip in ips if ip and ipaddress.ip_address(ip).is_global})
    now = s.datetime.now(s.TZ)
    cached = load_cache() if use_cache else {}
    results = {ip: cached[ip] for ip in addresses if ip in cached and cache_fresh(cached[ip], now)}
    pending = [ip for ip in addresses if ip not in results]
    if pending:
        results.update(query_primary(pending, key))
        missing = [ip for ip in pending if results[ip].get('status') != 'success']
        if missing:
            results.update(free_lookup(missing))
    if use_cache:
        cached.update({ip: value for ip, value in results.items() if value.get('status') == 'success'})
        save_cache({ip: value for ip, value in cached.items() if cache_fresh(value, now)})
    return results


def query_primary(addresses, key):
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
                    print(f'IP 信誉接口拒绝（HTTP {response.status_code}），停止查询；未确认字段保持未知', flush=True)
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


def normalize_free(ip, value):
    """把 ip-api.com 的字段对齐到 ipapi.is 的形状：没有纯净度，只有机房/移动/代理判定。"""
    if not isinstance(value, dict) or value.get('query') != ip or value.get('status') != 'success':
        return {'status': 'unknown', 'provider': 'ip-api.com', 'reason': 'invalid_response'}
    hosting, proxy, mobile = (value.get(key) if type(value.get(key)) is bool else None
                              for key in ('hosting', 'proxy', 'mobile'))
    return {'status': 'success', 'provider': 'ip-api.com', 'ip': ip,
            'checked_at': s.datetime.now(s.TZ).isoformat(timespec='seconds'),
            # 不是机房、不是代理、不是移动网络，按家用 ISP 处理，也就是住宅候选。
            'company_type': 'isp' if (hosting is False and proxy is False and mobile is False) else None,
            'asn_type': None, 'is_datacenter': hosting, 'is_mobile': mobile, 'is_proxy': proxy,
            'is_vpn': None, 'is_tor': None, 'is_abuser': None,
            'network_abuser_ratio': None, 'network_purity_score': None}


def free_lookup(ips):
    addresses = sorted({ip for ip in ips if ip and ipaddress.ip_address(ip).is_global})
    results = {ip: {'status': 'unknown', 'provider': 'ip-api.com', 'reason': 'lookup_unavailable'}
               for ip in addresses}
    with s.session() as client:
        for offset in range(0, len(addresses), 100):
            batch = addresses[offset:offset + 100]
            try:
                response = client.post(FREE_URL, params={'fields': FREE_FIELDS}, json=batch, timeout=20)
                response.raise_for_status()
                values = response.json()
            except (requests.RequestException, ValueError):
                print('备用 IP 归属查询失败，未确认字段保持未知', flush=True)
                continue
            if not isinstance(values, list):
                continue
            for item in values:
                ip = item.get('query') if isinstance(item, dict) else None
                if ip in results:
                    results[ip] = normalize_free(ip, item)
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
