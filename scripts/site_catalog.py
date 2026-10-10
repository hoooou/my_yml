"""Reviewed HTTPS entry pages and domain families shared by probes and routing."""


def site(url, markers, *domains):
    return {'url': url, 'markers': markers, 'domains': domains}


OVERSEAS = {
    'Google': site('https://www.google.com/', ('google',), 'google.com', 'googleapis.com', 'googleapis.cn', 'gstatic.com', 'googleusercontent.com'),
    'YouTube': site('https://www.youtube.com/', ('youtube',), 'youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com', 'youtube-nocookie.com'),
    'ChatGPT': site('https://chatgpt.com/', ('chatgpt', 'openai'), 'chatgpt.com', 'openai.com', 'oaistatic.com', 'oaiusercontent.com'),
    'Claude': site('https://claude.ai/', ('claude', 'anthropic'), 'claude.ai', 'anthropic.com'),
    'Gemini': site('https://gemini.google.com/', ('gemini',), 'gemini.google.com'),
    'GitHub': site('https://github.com/', ('github',), 'github.com', 'github.io', 'githubusercontent.com', 'githubassets.com'),
    'Wikipedia': site('https://www.wikipedia.org/', ('wikipedia',), 'wikipedia.org', 'wikimedia.org'),
    'Reddit': site('https://www.reddit.com/', ('reddit',), 'reddit.com', 'redd.it', 'redditstatic.com', 'redditmedia.com'),
    'X': site('https://x.com/', ('twitter', 'x.com', '<title>x</title>'), 'x.com', 'twitter.com', 'twimg.com', 't.co'),
    'Instagram': site('https://www.instagram.com/', ('instagram',), 'instagram.com', 'cdninstagram.com'),
    'Telegram': site('https://telegram.org/', ('telegram',), 'telegram.org', 't.me', 'telegra.ph', 'telegram.me'),
    'Discord': site('https://discord.com/', ('discord',), 'discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net'),
    'Facebook': site('https://www.facebook.com/', ('facebook',), 'facebook.com', 'fb.com', 'fbcdn.net', 'messenger.com'),
    'WhatsApp': site('https://www.whatsapp.com/', ('whatsapp',), 'whatsapp.com', 'whatsapp.net', 'wa.me'),
    'Netflix': site('https://www.netflix.com/', ('netflix',), 'netflix.com', 'nflxvideo.net', 'nflximg.net', 'nflxext.com', 'nflxso.net', 'nflximg.com'),
    'DisneyPlus': site('https://www.disneyplus.com/', ('disney',), 'disneyplus.com', 'dssott.com', 'bamgrid.com'),
    'Spotify': site('https://open.spotify.com/', ('spotify',), 'spotify.com', 'scdn.co', 'spotifycdn.com'),
    'TikTok': site('https://www.tiktok.com/', ('tiktok',), 'tiktok.com', 'tiktokcdn.com', 'tiktokv.com'),
    'Twitch': site('https://www.twitch.tv/', ('twitch',), 'twitch.tv', 'ttvnw.net', 'jtvnw.net'),
    'Amazon': site('https://www.amazon.com/', ('amazon',), 'amazon.com', 'primevideo.com', 'amazonvideo.com', 'aiv-cdn.net'),
    'Bing': site('https://www.bing.com/', ('bing',), 'bing.com', 'copilot.microsoft.com'),
    'Steam': site('https://store.steampowered.com/', ('steam',), 'steampowered.com', 'steamcommunity.com', 'steamstatic.com'),
    'StackOverflow': site('https://stackoverflow.com/', ('stack overflow', 'stackoverflow'), 'stackoverflow.com', 'stackexchange.com', 'sstatic.net'),
    'HuggingFace': site('https://huggingface.co/', ('hugging face', 'huggingface'), 'huggingface.co', 'hf.co'),
    'Perplexity': site('https://www.perplexity.ai/', ('perplexity',), 'perplexity.ai'),
    'Cursor': site('https://www.cursor.com/', ('cursor',), 'cursor.com', 'cursor.sh', 'cursorapi.com'),
}

DOMESTIC = {
    '百度': site('https://www.baidu.com/', ('baidu', '百度'), 'baidu.com', 'bdstatic.com', 'bdimg.com'),
    '哔哩哔哩': site('https://www.bilibili.com/', ('bilibili', '哔哩'), 'bilibili.com', 'bilibili.cn', 'hdslb.com', 'bilivideo.com'),
    '抖音': site('https://www.douyin.com/', ('douyin', '抖音'), 'douyin.com', 'douyincdn.com', 'douyinpic.com', 'douyinvod.com', 'zijieapi.com', 'ugurl.cn'),
    '微信': site('https://weixin.qq.com/', ('weixin', '微信'), 'qq.com', 'qpic.cn', 'qlogo.cn', 'wechat.com', 'tencent.com'),
    '淘宝': site('https://www.taobao.com/', ('taobao', '淘宝'), 'taobao.com', 'tmall.com', 'alicdn.com', 'alipay.com'),
    '京东': site('https://www.jd.com/', ('京东', 'jd.com'), 'jd.com', '360buyimg.com', 'jdcloud.com'),
    '知乎': site('https://www.zhihu.com/', ('zhihu', '知乎'), 'zhihu.com', 'zhimg.com'),
    '微博': site('https://weibo.com/', ('weibo', '微博'), 'weibo.com', 'weibo.cn', 'sinaimg.cn'),
    '腾讯视频': site('https://v.qq.com/', ('腾讯视频', 'qq.com'), 'video.qq.com'),
    '爱奇艺': site('https://www.iqiyi.com/', ('iqiyi', '爱奇艺'), 'iqiyi.com', 'iqiyipic.com', 'qiyipic.com'),
    '网易云音乐': site('https://music.163.com/', ('网易云音乐', 'music.163.com'), '163.com', '126.net', 'music.126.net'),
    '小红书': site('https://www.xiaohongshu.com/', ('xiaohongshu', '小红书'), 'xiaohongshu.com', 'xhscdn.com'),
    'DeepSeek': site('https://www.deepseek.com/', ('deepseek',), 'deepseek.com'),
    'Gitee': site('https://gitee.com/', ('gitee',), 'gitee.com', 'gitee.cn'),
}

PAGES = {**OVERSEAS, **DOMESTIC}
