import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import routing as r
from app_catalog import DIRECT_APPS, PROXY_APPS
from site_catalog import OVERSEAS, DOMESTIC
from urllib.parse import urlparse


class RoutingTests(unittest.TestCase):
    def test_requested_android_apps_and_desktop_aliases_are_fixed_before_service_rules(self):
        config = {'rules': [], 'rule-providers': {'reject': {}, 'private': {}, 'applications': {}}}
        r.optimize_routing(config)
        providers, rules = config['rule-providers'], config['rules']
        direct = providers['app-direct']['payload']
        proxy = providers['app-proxy']['payload']
        for package in ('com.tencent.mm', 'com.sina.weibo', 'com.sankuai.meituan',
                        'com.xunmeng.pinduoduo', 'com.jingdong.app.mall', 'com.autonavi.minimap',
                        'com.tencent.wework', 'com.oray.sunlogin', 'com.tencent.wemeet.app'):
            self.assertIn('PROCESS-NAME,' + package, direct)
        for package in ('com.twitter.android', 'com.android.vending', 'com.google.android.gms', 'com.google.android.gsf',
                        'com.google.android.youtube', 'com.instagram.barcelona'):
            self.assertIn('PROCESS-NAME,' + package, proxy)
        for name in ('WeChat', 'WeChatAppEx.exe', 'TencentMeeting', 'wemeetapp.exe', 'SunloginClient',
                     'SunloginClient_Desktop', 'SunloginClient_Helper', 'SunloginClient_Desktop.exe',
                     'SunloginClient_Service.exe', 'WXWork.exe'):
            self.assertIn('PROCESS-NAME,' + name, direct)
        self.assertIn('PROCESS-NAME,Cursor Helper (Renderer)', proxy)
        self.assertFalse(set(direct) & set(proxy))
        self.assertNotIn('PROCESS-NAME,com.tencent.wemeet', direct)
        for payload in (direct, proxy):
            self.assertTrue(all(len(rule.split(',')) == 2 for rule in payload))
            for name in ('chrome.exe', 'Safari', 'python', 'node', 'git', 'Helper'):
                self.assertNotIn('PROCESS-NAME,' + name, payload)
        for app_rule in ('RULE-SET,app-direct,DIRECT', 'RULE-SET,app-proxy,' + r.GLOBAL):
            self.assertLess(rules.index('RULE-SET,company-internal,DIRECT'), rules.index(app_rule))
            self.assertLess(rules.index('RULE-SET,reject,REJECT'), rules.index(app_rule))
            self.assertLess(rules.index(app_rule), rules.index('RULE-SET,overseas-services,' + r.GLOBAL))
            self.assertLess(rules.index(app_rule), rules.index('RULE-SET,domestic-services,DIRECT'))
        self.assertEqual(config['find-process-mode'], 'strict')

    def test_app_domain_fallback_and_dns_cover_every_catalog_entry(self):
        config = {}
        r.optimize_routing(config)
        for catalog, name, dns in ((DIRECT_APPS, 'app-direct', r.CHINA_DNS),
                                    (PROXY_APPS, 'app-proxy', r.PROXY_DNS)):
            payload = config['rule-providers'][name + '-domains']['payload']
            for item in catalog.values():
                self.assertTrue(all('+.' + domain in payload for domain in item['domains']))
            self.assertEqual(config['dns']['nameserver-policy']['rule-set:' + name + '-domains'], dns)
        self.assertIn('+.oray.com', config['rule-providers']['app-direct-domains']['payload'])
        self.assertIn('+.gvt1.com', config['rule-providers']['app-proxy-domains']['payload'])
        self.assertIn('+.threads.com', config['rule-providers']['app-proxy-domains']['payload'])

    def test_personal_process_exceptions_survive_daily_compile_and_take_precedence(self):
        exceptions = ['PROCESS-NAME,WeChat,REJECT', 'PROCESS-PATH,/opt/custom/app,DIRECT',
                      'PROCESS-NAME-REGEX,^MyApp.*,DIRECT', 'PROCESS-PATH-WILDCARD,/opt/custom/*,DIRECT']
        config = {'rules': exceptions + ['DOMAIN-SUFFIX,office.com,DIRECT']}
        r.optimize_routing(config)
        rules = config['rules']
        for rule in exceptions:
            self.assertLess(rules.index(rule), rules.index('RULE-SET,app-direct,DIRECT'))
            self.assertGreater(rules.index(rule), rules.index('RULE-SET,company-internal,DIRECT'))
        first = copy.deepcopy(config)
        r.optimize_routing(config)
        self.assertEqual(config, first)

    def test_reviewed_services_override_old_direct_rules_without_extra_groups(self):
        config = {'rules': ['DOMAIN-SUFFIX,cursor.sh,DIRECT', 'DOMAIN-KEYWORD,tencent,DIRECT',
                           'DOMAIN-SUFFIX,office.com,DIRECT', 'DOMAIN-SUFFIX,googleapis.cn,DIRECT', 'MATCH,DIRECT'],
                  'rule-providers': {'unused': {}, 'applications': {}, 'direct': {}}}
        r.optimize_routing(config)
        rules = config['rules']
        self.assertNotIn('DOMAIN-SUFFIX,cursor.sh,DIRECT', rules)
        self.assertNotIn('DOMAIN-KEYWORD,tencent,DIRECT', rules)
        self.assertIn('DOMAIN-SUFFIX,office.com,DIRECT', rules)
        self.assertLess(rules.index('RULE-SET,overseas-services,🚀 全局选择'), rules.index('RULE-SET,applications,DIRECT'))
        self.assertLess(rules.index('RULE-SET,gfw,🚀 全局选择'), rules.index('RULE-SET,direct,DIRECT'))
        self.assertEqual(rules[-1], 'MATCH,🚀 全局选择')
        self.assertNotIn('unused',config['rule-providers'])
        self.assertNotIn('proxy-groups',config)
        for catalog, name in [(OVERSEAS,'overseas-services'),(DOMESTIC,'domestic-services')]:
            payload=config['rule-providers'][name]['payload']
            for item in catalog.values():
                host=urlparse(item['url']).hostname
                self.assertTrue(any(host==domain[2:] or host.endswith('.'+domain[2:]) for domain in payload),host)
        self.assertIn('+.oaistatic.com',config['rule-providers']['overseas-services']['payload'])
        first=copy.deepcopy(config)
        r.optimize_routing(config)
        self.assertEqual(config,first,'daily compilation should be idempotent')

    def test_dns_bootstrap_is_independent_of_proxy_and_foreign_queries_use_proxy(self):
        config={'dns':{'default-nameserver':['192.168.70.49','8.8.8.8'],'ipv6':True},'rules':[]}
        r.optimize_routing(config)
        dns=config['dns']
        self.assertEqual(dns['default-nameserver'],['223.5.5.5','119.29.29.29'])
        self.assertEqual(dns['proxy-server-nameserver'],r.CHINA_DNS)
        self.assertEqual(dns['direct-nameserver'],r.CHINA_DNS)
        self.assertEqual(dns['nameserver-policy']['rule-set:domestic-services'],r.CHINA_DNS)
        self.assertEqual(dns['nameserver-policy']['rule-set:overseas-services'],r.PROXY_DNS)
        self.assertTrue(all('#🚀 全局选择' in url for url in dns['fallback']))
        self.assertTrue(dns['ipv6'])

    def test_company_policy_overrides_public_resolvers_and_survives_daily_compilation(self):
        config = {'dns': {'nameserver-policy': {'+.bitauto.com': r.CHINA_DNS,
                                               '+.office.com': ['system']}},
                  'rules': ['DOMAIN-SUFFIX,bitauto.com,REJECT'],
                  'proxy-groups': [{'name': 'existing', 'type': 'select', 'proxies': ['DIRECT']}]}
        groups = copy.deepcopy(config['proxy-groups'])
        r.optimize_routing(config)
        self.assertEqual(config['rules'][0], 'RULE-SET,company-internal,DIRECT')
        dns = config['dns']
        for domain in r.COMPANY_DOMAINS:
            self.assertEqual(dns['nameserver-policy']['+.' + domain], r.COMPANY_DNS)
            self.assertIn('+.' + domain, dns['fake-ip-filter'])
        self.assertEqual(dns['nameserver-policy']['rule-set:company-internal'], r.COMPANY_DNS)
        self.assertEqual(list(dns['nameserver-policy'])[:5],
                         ['+.' + domain for domain in r.COMPANY_DOMAINS] + ['rule-set:company-internal'])
        self.assertTrue(dns['direct-nameserver-follow-policy'])
        self.assertEqual(dns['nameserver-policy']['+.office.com'], ['system'])
        self.assertEqual(dns['nameserver'], r.CHINA_DNS)
        self.assertEqual(config['proxy-groups'], groups)
        self.assertEqual(config['rule-providers']['company-internal']['behavior'], 'domain')
        self.assertFalse(any(rule.startswith('DOMAIN-KEYWORD,')
                             for rule in config['rule-providers']['company-internal']['payload']))
        compiled = copy.deepcopy(config)
        r.optimize_routing(config)
        self.assertEqual(config, compiled)
