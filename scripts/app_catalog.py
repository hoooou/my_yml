"""Reviewed exact Android packages and desktop executables (2026-10-10).

macOS reference: https://github.com/Clash-FX/cn-apps-direct (MIT).
Android reference: https://gist.github.com/Zestinc/fa5a35a444a076214cefbe4965677d8b
Packages are also identified by official Play/store listings; local Info.plist
confirms WeChat, QQ, TencentMeeting, Telegram, Claude and Cursor on this Mac.
Domain reference: https://github.com/blackmatrix7/ios_rule_script
Content-search audit and pinned evidence: docs/process-rule-sources.md
These are reviewed snapshots, not unfiltered third-party process subscriptions.
Only bare executable names belong here, never macOS bundle identifiers.
"""


def app(packages, desktop=(), domains=()):
    return {'packages': tuple(packages), 'desktop': tuple(desktop), 'domains': tuple(domains)}


DIRECT_APPS = {
    '微信': app(['com.tencent.mm'], ['WeChat', 'Weixin', 'WeChatAppEx', 'WeChat.exe', 'Weixin.exe', 'WeChatAppEx.exe'],
              ['wechat.com', 'weixin.com', 'weixin.qq.com', 'servicewechat.com', 'weixinbridge.com', 'tenpay.com']),
    '微博': app(['com.sina.weibo'], domains=['weibo.com', 'weibo.cn', 'sinaimg.cn', 'weibocdn.com']),
    '美团': app(['com.sankuai.meituan', 'com.dianping.v1'], ['Meituan'],
              ['meituan.com', 'meituan.net', 'sankuai.com', 'dianping.com']),
    '拼多多': app(['com.xunmeng.pinduoduo'], domains=['pinduoduo.com', 'yangkeduo.com', 'pddpic.com']),
    '京东': app(['com.jingdong.app.mall'], domains=['jd.com', '360buyimg.com']),
    '高德地图': app(['com.autonavi.minimap'], domains=['amap.com', 'autonavi.com']),
    '企业微信': app(['com.tencent.wework'], ['WeCom', '企业微信', 'WXWork.exe'], ['work.weixin.qq.com']),
    '向日葵': app(['com.oray.sunlogin'], ['SunloginClient', 'SunloginClient.exe', 'sunloginclient',
              'SunloginClient_Desktop', 'SunloginClient_Helper', 'SunloginClient_Desktop.exe', 'SunloginClient_Service.exe'],
              ['oray.com', 'oray.net']),
    '腾讯会议': app(['com.tencent.wemeet.app'], ['TencentMeeting', 'wemeetapp', 'wemeetapp.exe'],
                ['meeting.tencent.com', 'wemeet.qq.com']),
    'QQ': app(['com.tencent.mobileqq'], ['QQ', 'QQ.exe', 'TIM', 'TIM.exe'], ['qq.com', 'qpic.cn', 'qlogo.cn']),
    '支付宝': app(['com.eg.android.AlipayGphone'], domains=['alipay.com', 'alipayobjects.com']),
    '淘宝': app(['com.taobao.taobao'], domains=['taobao.com', 'tbcdn.cn', 'alicdn.com']),
    '哔哩哔哩': app(['tv.danmaku.bili'], ['哔哩哔哩', 'Bilibili'], ['bilibili.com', 'bilivideo.com', 'hdslb.com']),
    '抖音': app(['com.ss.android.ugc.aweme'], domains=['douyin.com', 'douyinvod.com']),
    '网易云音乐': app(['com.netease.cloudmusic'], ['NeteaseMusic', 'cloudmusic.exe'], ['music.163.com', 'music.126.net']),
    '小红书': app(['com.xingin.xhs'], domains=['xiaohongshu.com', 'xhscdn.com']),
}

PROXY_APPS = {
    'X / Twitter': app(['com.twitter.android'], domains=['x.com', 'twitter.com', 't.co', 'twimg.com']),
    # Play downloads/login often originate in Google Play services instead of the store.
    'Google Play': app(['com.android.vending', 'com.google.android.gms', 'com.google.android.gsf'],
                       domains=['googleplay.com', 'play.google.com', 'gvt1.com', 'gvt2.com', 'ggpht.com']),
    'YouTube': app(['com.google.android.youtube'], domains=['youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com']),
    'Threads': app(['com.instagram.barcelona'], domains=['threads.net', 'threads.com']),
    'Telegram': app(['org.telegram.messenger'], ['Telegram', 'Telegram.exe'], ['telegram.org', 't.me', 'telegram.me']),
    'Discord': app(['com.discord'], ['Discord', 'Discord.exe'], ['discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net']),
    'Instagram': app(['com.instagram.android'], domains=['instagram.com', 'cdninstagram.com']),
    'ChatGPT': app(['com.openai.chatgpt'], ['ChatGPT', 'ChatGPT.exe'], ['chatgpt.com', 'openai.com', 'oaistatic.com', 'oaiusercontent.com']),
    'Claude': app(['com.anthropic.claude'], ['Claude', 'Claude.exe', 'Claude Helper', 'Claude Helper (GPU)',
                     'Claude Helper (Plugin)', 'Claude Helper (Renderer)'], ['claude.ai', 'anthropic.com']),
    'Gemini': app(['com.google.android.apps.bard'], domains=['gemini.google.com', 'generativelanguage.googleapis.com']),
    'Cursor': app([], ['Cursor', 'Cursor.exe', 'Cursor Helper', 'Cursor Helper (GPU)',
                      'Cursor Helper (Renderer)', 'Cursor Helper (Plugin)'], ['cursor.com', 'cursor.sh']),
}


def process_payload(catalog):
    """Classical provider payloads are matchers only, with no routing policy."""
    return ['PROCESS-NAME,' + name for name in sorted({
        name for item in catalog.values() for name in (*item['packages'], *item['desktop'])})]


def domain_payload(catalog):
    return ['+.' + domain for domain in sorted({
        domain for item in catalog.values() for domain in item['domains']})]
