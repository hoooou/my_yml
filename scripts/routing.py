"""Compile mobile routing without adding strategy groups or geosite dependencies."""
from site_catalog import OVERSEAS, DOMESTIC
from app_catalog import DIRECT_APPS, PROXY_APPS, process_payload, domain_payload

GLOBAL = '🚀 全局选择'
CHINA_DNS = ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query']
PROXY_DNS = [f'https://1.1.1.1/dns-query#{GLOBAL}', f'https://8.8.8.8/dns-query#{GLOBAL}']
COMPANY_DOMAINS = ('tech.bitauto.com', 'yiche.com', 'bitauto.com', 'bitautotech.com')
COMPANY_DNS = ['192.168.70.49', '192.168.70.1']


def domains(catalog):
    return sorted({domain for item in catalog.values() for domain in item['domains']})


def optimize_routing(config):
    """Company/LAN first, then fixed app choices, then service-domain fallback."""
    providers = config.setdefault('rule-providers', {})
    config['find-process-mode'] = 'strict'
    for name, catalog in [('app-direct', DIRECT_APPS), ('app-proxy', PROXY_APPS)]:
        providers[name] = {'type': 'inline', 'behavior': 'classical', 'format': 'yaml',
                           'payload': process_payload(catalog)}
        providers[name + '-domains'] = {'type': 'inline', 'behavior': 'domain', 'format': 'yaml',
                                      'payload': domain_payload(catalog)}
    # Exact domain families also work in DNS policy and fake-IP filtering.
    # Avoid keyword matching unrelated domains containing a company name.
    providers['company-internal'] = {'type': 'inline', 'behavior': 'domain', 'format': 'yaml',
                                     'payload': ['+.' + domain for domain in COMPANY_DOMAINS]}
    for name, catalog in [('overseas-services', OVERSEAS), ('domestic-services', DOMESTIC)]:
        providers[name] = {'type': 'inline', 'behavior': 'domain', 'format': 'yaml',
                           'payload': ['+.' + domain for domain in domains(catalog)]}
    # Reuse the established maintained lists; gfw was previously declared but unused.
    providers.setdefault('gfw', {'type': 'http', 'behavior': 'domain', 'format': 'yaml',
        'url': 'https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt',
        'path': './ruleset/gfw.yaml', 'interval': 86400})
    def rule_set(name, target, no_resolve=False):
        return [f'RULE-SET,{name},{target}' + (',no-resolve' if no_resolve else '')] if name in providers else []
    custom, process_custom = [], []
    for rule in config.get('rules', []):
        if rule.startswith(('PROCESS-NAME,', 'PROCESS-PATH,', 'PROCESS-NAME-REGEX,',
                            'PROCESS-PATH-REGEX,', 'PROCESS-NAME-WILDCARD,', 'PROCESS-PATH-WILDCARD,')):
            process_custom.append(rule)
            continue
        if not rule.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,')):
            continue
        # Broad substrings cause collateral direct routing; service families cover Tencent.
        if rule in ('DOMAIN-KEYWORD,tencent,DIRECT', 'DOMAIN-KEYWORD,yuanbao,DIRECT'):
            continue
        if rule in ('DOMAIN-SUFFIX,cursor.sh,DIRECT', 'DOMAIN-SUFFIX,cursor.com,DIRECT'):
            continue
        custom.append(rule)
    rules = (rule_set('company-internal', 'DIRECT')
             + rule_set('private', 'DIRECT') + rule_set('lancidr', 'DIRECT', True)
             + ['GEOIP,LAN,DIRECT,no-resolve'] + rule_set('reject', 'REJECT')
             + process_custom + rule_set('app-proxy', GLOBAL) + rule_set('app-direct', 'DIRECT')
             + rule_set('app-proxy-domains', GLOBAL) + rule_set('app-direct-domains', 'DIRECT')
             + rule_set('overseas-services', GLOBAL) + rule_set('domestic-services', 'DIRECT')
             + custom + rule_set('applications', 'DIRECT') + rule_set('icloud', 'DIRECT')
             + rule_set('apple', 'DIRECT') + rule_set('google', GLOBAL)
             + rule_set('proxy', GLOBAL) + rule_set('gfw', GLOBAL)
             + rule_set('direct', 'DIRECT') + rule_set('telegramcidr', GLOBAL, True)
             + rule_set('cncidr', 'DIRECT') + ['GEOIP,CN,DIRECT', f'MATCH,{GLOBAL}'])
    config['rules'] = list(dict.fromkeys(rules))
    referenced = {rule.split(',')[1] for rule in rules if rule.startswith('RULE-SET,')}
    config['rule-providers'] = {key: value for key, value in providers.items() if key in referenced}
    dns = config.setdefault('dns', {})
    dns.update({'enable': True, 'default-nameserver': ['223.5.5.5', '119.29.29.29'],
                'proxy-server-nameserver': list(CHINA_DNS), 'direct-nameserver': list(CHINA_DNS),
                'direct-nameserver-follow-policy': True,
                'nameserver': list(CHINA_DNS), 'fallback': list(PROXY_DNS),
                'fallback-filter': {'geoip': True, 'geoip-code': 'CN',
                                    'ipcidr': ['240.0.0.0/4', '0.0.0.0/32']}})
    # Policy matching follows YAML order: company choices must precede broad lists.
    policy = {'+.' + domain: list(COMPANY_DNS) for domain in COMPANY_DOMAINS}
    policy['rule-set:company-internal'] = list(COMPANY_DNS)
    policy['rule-set:app-proxy-domains'] = list(PROXY_DNS)
    policy['rule-set:app-direct-domains'] = list(CHINA_DNS)
    policy.update({f'rule-set:{name}': list(PROXY_DNS) for name in ('overseas-services', 'proxy', 'gfw') if name in referenced})
    policy.update({f'rule-set:{name}': list(CHINA_DNS) for name in ('domestic-services', 'direct', 'private') if name in referenced})
    # Retain explicitly configured per-domain resolver choices if any.
    policy.update({key: value for key, value in dns.get('nameserver-policy', {}).items()
                   if not key.startswith('rule-set:') and key not in policy})
    dns['nameserver-policy'] = policy
    dns.setdefault('enhanced-mode', 'fake-ip')
    dns.setdefault('fake-ip-range', '198.18.0.1/16')
    filters = dns.get('fake-ip-filter', [])
    dns['fake-ip-filter'] = list(dict.fromkeys(filters + ['*.lan', '*.local', '+.msftconnecttest.com', '+.msftncsi.com']
                                             + ['+.' + domain for domain in COMPANY_DOMAINS]
                                             + ['rule-set:company-internal']))
