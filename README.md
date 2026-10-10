# Clash 节点优选

`聚合配置.yaml` 是原订阅源和分流规则的输入，`节点来源.yaml` 是新增的公开免费来源清单；`优选配置.yaml` 是自动筛选后可直接导入的完整配置，适用于 Clash Meta / Mihomo 客户端。

## 使用

在客户端中添加远程配置：

```
https://raw.githubusercontent.com/hoooou/my_yml/main/%E4%BC%98%E9%80%89%E9%85%8D%E7%BD%AE.yaml
```

将客户端的远程配置刷新间隔设为 24 小时。GitHub 更新文件后，客户端仍需要刷新才能加载新节点。

手机保留 **5 个分组**，默认在“🚀 全局选择”使用“⭐ 综合优选”；需要台湾或新加坡时改选“🌏 台湾／新加坡”。刷新原订阅即可生效。

| 分组 | 用途 |
|---|---|
| 🚀 全局选择 | 选择当前使用哪类节点，默认综合优选 |
| ⭐ 综合优选 | 完整通过 1 MB，且满足三轮海外响应质量门槛；按网站响应耗时和稳定性排序，不回退到失败节点 |
| ⚡ 高速下载 | 综合合格池中，在 20 秒内完整下载 50 MB，按此次速度排序 |
| 🏠 非机房 IP | 综合合格池中明确不是机房的独立出口，按出口 IP 去重 |
| 🌏 台湾／新加坡 | 已确认出口在 TW/SG，保留访问和下载必过条件，允许较慢网页响应，不限数量 |

综合、高速和非机房共用国内 TCP 明确通过、1 MB 完整通过、海外网站响应合格的严格节点池。台湾／新加坡组使用单独的地区门槛；仅满足地区门槛的节点只放进地区组，不放进其他节点组。达不到任一入选门槛的节点定义和凭据不写入订阅，仅在报告保留检测结果；每日重新获取全部来源，恢复的节点仍可入选。香港整体最多 30 个，其他地区不限数量；数量政策不减少任何节点的检测。筛选依据、当前门槛及后续建议见 [面向中国移动的筛选方案](docs/node-selection-plan.md)。

地区组仍要求 **204 三轮、国内 TCP、截图指定13个海外网站各三轮访问、1 MB 下载全部通过**，且没有已发现的出口地区/IP矛盾。Google/YouTube 中位耗时放宽到 **3 秒**，最慢一轮到 **5 秒**，极差到 **3 秒**；13个指定网站均必过，不以其他站或trace替代。403、验证码、慢响应状态、失败或未测不放行，不按节点原名猜地区。50 MB 不是地区组入选条件。没有合格节点时显示 `REJECT`，不补入失败节点；若只有地区组有节点，全局默认选地区组。

移除按地区选择、TCP通、TCP不通、TCP未验证及全部节点分组，节点名称仍保留国家标签。JSON 报告保留逐节点、逐网站完整结果及 TCP 分类，Markdown 展示网站覆盖和节点概要。检测与域名分流共用审核后的清单，见 `scripts/site_catalog.py`。

## 每日更新

GitHub Actions 的“每日节点连通性分类”每天北京时间 **08:00 开始**，也支持手动触发。四个免费标准 Actions 分片并行，每片最多同时处理 16 个节点；同一节点按下面的顺序过关，不同节点可以同时处于不同阶段，不等待全量上一阶段结束。

1. 获取原配置 11 个来源和新增 6 个公开来源的最新节点，按连接配置去重；不同密码、UUID、协议或传输参数保留。内核不支持或包含非法控制字符的节点在报告记录，不写入手机订阅。
2. **先批量检查 HTTPS 204，独立请求三轮**：`https://connectivitycheck.gstatic.com/generate_204`。三次均返回无正文的 204 才继续；记录每轮延迟、中位数和最大值。不通过的节点延迟显示未知，分类及跳过原因保留在 JSON 报告，不伪造国内入口失败。
3. **再进行国内 TCPing**：仅对 204 通过且支持 TCP 的主机/端口调用小小 API，一入口一次。共享入口只提交一次，不同凭据的节点独立检查 204 和后续访问。四片合计约不超过 5 次请求/秒。明确连接失败记为“不通”，接口限流、异常、超时或目标不匹配记为“未验证”。UDP 的 TCP 阶段不适用，仅在报告保留；当前必须有 TCP 通过证据才发布。
4. **再检查 26 个海外网站各三轮，13 个国内网站和两个 trace 各一次**。海外为原十站，以及 Telegram、Discord、Facebook、WhatsApp、Netflix、DisneyPlus、Spotify、TikTok、Twitch、Amazon、Bing、Steam、StackOverflow、HuggingFace、Perplexity、Cursor；国内为百度、哔哩哔哩、微信、淘宝、京东、知乎、微博、腾讯视频、爱奇艺、网易云音乐、小红书、DeepSeek、Gitee。每节点最多 **5 个请求并发**，地址增加时分批执行。参考 [EDT 页面](https://edt-pages.github.io/admin/) 的国内/国际覆盖思路，但验证首页 HTML 和站点标识，不把图标响应当作功能可用。Amazon读取最多64 KB、其余网站最多16 KB的响应样本，要求正确域名、200、HTML；分别记录到响应头的耗时（近似首字节时间）、样本接收耗时与字节数。响应头超过 3 秒或样本接收超过 5 秒记为响应慢，不能作为稳定通过；最多跟随两次 HTTPS 跳转，仅允许入口域名和对应 www/非 www 域名；其他跨域跳转、403/412/429/444/451、验证码或风控记为需复核。脚本的 captcha 开关不会误判为验证码。请求使用项目 bot 标识，符合 [Wikimedia 的要求](https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Foundation_User-Agent_Policy)。trace 必须匹配预期域名、公网出口、地区和 HTTPS；通过只说明连通，不证明登录、对话或视频播放可用。海外排名仅统计 26 个海外页面，不要求全部通过；国内站经当前节点回访，仅供对照，不代表手机直连或移动实测，不参与海外评分，也不能单独触发下载。
5. **最后 Cloudflare 快速下载一次**：TCP 通且指定13个海外网页三轮全部通过后，通过同一个节点访问 [官方 1 MB 下载地址](https://speed.cloudflare.com/__down?bytes=1000000)。请求禁止重定向和压缩，响应状态、类型、声明长度及完整字节数都匹配才通过。读取超时 1 秒，采样预算 6 秒；达到预算就停止读取，底层建连/读取还可能等待其自身超时。记录完整 1 MB 的速度及耗时，包含 TLS 与首字节等待，属于快速采样速度，不是峰值带宽。
6. **50 MB 高速下载复测**：只对第 5 步完整通过 1 MB 的节点，下载 [Cloudflare 50 MB 文件](https://speed.cloudflare.com/__down?bytes=50000000)一次。单次预算 **20 秒**、读取超时 1 秒，每个 Actions 分片最多 **2 个同时下载**（四片总共最多 8 个），减少大文件测试相互抢占带宽。要求完整 50,000,000 字节、响应状态/类型/长度匹配且在预算内完成；半截下载、超时或连接失败均不入选。单独的“⚡ 高速下载”组按这次 50 MB 实测速度从高到低排序，**香港最多 30 个，其他地区保留全部通过节点**。速度包含建连和首字节等待，仍是 GitHub 云端测量。节点名称优先使用合格 50 MB 的 Mbps 速度，否则使用原 1 MB 快测速度；采样来源保留在 JSON。重建旧结果时也按 20 秒筛选高速组，但不改写原始检测记录或实际测量预算；报告单独列出当前入选政策。
7. 严格合格池要求国内 TCP 明确通过、1 MB 完整下载通过，以及指定13个海外网站各三轮均通过；Google/YouTube中位样本耗时不超过 1.5 秒、最慢一轮不超过 3 秒、三轮耗时极差不超过 1.5 秒；其余海外网站保留检测结果。再比较核心站最差尾延迟、中位耗时和波动、其他海外稳定站的耗时、覆盖数量、204 延迟与下载速度。另按上述地区门槛选取台湾／新加坡节点。不满足任一门槛的节点不写入订阅或任何组；两类门槛均无合格节点时保留旧订阅，不伪造通过或回退到失败节点。高速和非机房均只从严格合格池选取。非机房组要求明确 `hosting=false`、不同 trace 未发现出口不一致，并按独立出口 IP 去重；仅香港最多 30 个，其他地区不限数量。未确认 IP 类型不进入非机房组。
8. 四片结果全部合并，检查批次、完整覆盖、各阶段顺序和轮数、下载完整性。缺片或漏测拒绝发布。Mihomo 最终配置校验通过后，更新原订阅和 `连通性报告.json/md`。分片临时文件保留 1 天。

Cloudflare 官方测速引擎使用 `https://speed.cloudflare.com/__down`，`bytes` 参数指定字节数，见[官方项目](https://github.com/cloudflare/speedtest)。本流程先用 1,000,000 字节（1 MB），通过后再用 50,000,000 字节（50 MB），无需安装或调用 clash-speedtest。

探测服务：

| 服务 | 当前用途 |
|---|---|
| [小小 API](https://xxapi.cn/doc/tcping) | 国内 TCPing 自动分类；运营商未公开，不能称为移动线路实测 |
| [ITDOG](https://www.itdog.cn/batch_tcping/) | 网页人工对照；未接入可用的全量自动接口 |
| [TCPING.CN](https://www.tcping.cn/tcping) | 网页人工对照；自动接口要求人机验证时跳过 |

每轮记录另外两家服务状态，不宣称三家都完成自动探测，不绕过人机验证。用户已经本地对照，确认 TCPing 分类有参考价值，当前将其作为入口必过条件；服务未公开运营商，报告仍标真实探测来源。海外访问和下载速度来自 GitHub 云端，网站排序可继续结合手机体验校准。

发布前检查所有解码字段，剔除非法控制字符，避免 FlClash 重新生成配置后报 `control characters are not allowed`。正常中文和图标保留。手动触发选择 `repair` 重建已有配置，不重复节点测速；配置 Key 后仅补查 IP 信誉，保留原节点测量时间、原轮数和原下载设置；每日任务及默认 `full` 执行最新分阶段流程。

`测速报告.*`、`移动小测报告.*` 是历史结果，以 `连通性报告.*` 为准。手机订阅地址保留；所有来源失效或配置不能校验时保留旧订阅。

手动选择 `claude-diagnostics` 可对指定已完成全量测试进行小样本诊断：从实际 trace 确认的不同出口地区选择节点，对照原请求、只改变 User-Agent 的请求、curl HTTP/1.1 与 HTTP/2，以及普通无头 Chrome。前后均检查204和Claude trace；保存响应状态、验证页信号和安全的跳转信息，不保存Cookie或节点凭据。诊断模式不修改订阅，不把403、验证码或trace算成Claude首页通过。全量输入和报告的临时文件过期后，需要使用新的全量运行编号。

## 手机分流与 DNS

匹配顺序：公司域名直连 → 局域网和私有域名直连 → 保留广告拦截 → 个人进程例外 → 指定应用进程直连/代理 → 应用域名兜底 → 明确的海外服务走“🚀 全局选择” → 国内服务直连 → 个人域名例外 → 其他应用、Apple/iCloud、代理/GFW/国内维护规则集 → 中国 IP 直连 → 未匹配流量走全局选择。海外 AI、影音、社交和开发服务包含常用 API、登录、静态资源及 CDN 域名，检测和分流共用清单。保留 Office、OneDrive、SharePoint 等个人域名直连选择；Cursor 进程及服务域名代理，移除 Tencent/元宝模糊关键词直连，启用原来未引用的 GFW 列表。没有增加应用策略组。

### 指定应用分流

应用清单位于 `scripts/app_catalog.py`，同时生成 Android 包名、macOS/Windows 可执行文件名以及域名兜底。每日全量发布和手动 `repair` 均编译同一清单，手机继续更新原订阅即可。

| 选择 | 应用 |
|---|---|
| 指定直连 | 微信、微博、美团/大众点评、拼多多、京东、高德地图、企业微信、向日葵、腾讯会议 |
| 补充直连 | QQ/TIM、支付宝、淘宝、哔哩哔哩、抖音、网易云音乐、小红书 |
| 指定代理 | X/Twitter、Google Play、YouTube、Threads |
| 补充代理 | Telegram、Discord、Instagram、ChatGPT、Claude、Gemini、Cursor |

进程规则在常规服务域名规则前：例如微信内打开的海外链接仍按微信直连选择；公司域名和局域网始终优先直连。Google Play 包含商店 `com.android.vending`、服务 `com.google.android.gms` 和框架 `com.google.android.gsf`，相关 Google 后台服务也走代理。浏览器没有整进程固定直连或代理，继续按访问域名分流。未识别进程时回退到域名规则；此时无法保证该应用使用的每个第三方域名都遵循进程选择。

设置 `find-process-mode: strict`，按规则需要查进程。Android 使用完整包名；macOS 使用实际可执行文件名，不使用 bundle ID。本机核对了 WeChat、QQ、TencentMeeting、Telegram、Claude、Cursor 及 Claude/Cursor 的专属 Helper 名称；没有匹配通用 `Helper`、浏览器、Python、Node 或 Git。个人直接写入的 `PROCESS-NAME`/`PROCESS-PATH` 及正则/通配符例外会保留，并优先于内置应用清单。

参考 [Clash-FX/cn-apps-direct](https://github.com/Clash-FX/cn-apps-direct) 的 macOS 进程名称清单、[Android 包名参考](https://gist.github.com/Zestinc/fa5a35a444a076214cefbe4965677d8b)及官方应用商店信息，服务域名参考 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)。这是 2026-10-10 审核适配后的内置快照，不自动导入外部清单的全部路由选择；第三方原文中的策略字段也不会写入 classical provider 的 matcher。原有 Loyalsoldier 域名/IP 规则集仍自动更新。

随后按实际代码内容搜索 `PROCESS-NAME`、Android 包名和可执行文件名，补充核对隐藏在个人配置、生成规则和辅助脚本中的清单。来源固定提交、文件更新时间及不采用的写法见 [进程规则代码搜索核对记录](docs/process-rule-sources.md)。本轮补充向日葵 Desktop/Helper/Service 别名、Windows 微信 `WeChatAppEx.exe` 以及 Google 服务框架；这是兼容名称补充，手机实际识别仍需本地连接日志确认。

FlClash 需使用规则模式，并让这些应用的流量进入其 VPN；在“分应用代理”中排除的应用不会经过订阅规则。Android 进程识别依赖系统支持，旧系统可能只能域名兜底。电脑进程流量需进入 Mihomo（通常使用 TUN），客户端覆写也可能改变最终规则。本次校验配置和桌面进程匹配，不宣称已经验证你手机上全部应用的实际识别。依据 [Mihomo PROCESS-NAME 文档](https://wiki.metacubex.one/config/rules/#process-name)和 [FlClash VPN 实现](https://github.com/chen08209/FlClash/blob/main/android/service/src/main/java/com/follow/clash/service/VpnService.kt)。

国内 DNS 和节点域名使用阿里/腾讯 DoH，引导 DNS 为 `223.5.5.5` 与 `119.29.29.29`，公司 DNS 不作为公共域名的引导解析器。海外 DNS 查询通过全局选择的节点访问加密 DNS；独立节点域名解析器避免代理与 DNS 互相依赖。保留原 IPv6 选择，加入局域网及 Windows 网络检查域名的 fake-IP 排除。依据 [Mihomo DNS 文档](https://wiki.metacubex.one/config/dns/)和[规则集合文档](https://wiki.metacubex.one/config/rule-providers/)；服务域名内置，维护规则集继续每天更新。

公司域名 `tech.bitauto.com`、`yiche.com`、`bitauto.com`、`bitautotech.com` 及其子域名优先直连，单独使用 `192.168.70.49` 和 `192.168.70.1`，并排除 fake-IP。DNS 策略与规则随每日订阅一起生成，不依赖 Clash Verge 的本地覆写；设置 `direct-nameserver-follow-policy: true`，防止直连解析改用公共 DNS。使用精确域名后缀，避免公司关键词误匹配无关网站。这两个私有 DNS 地址需要公司网络或能够访问公司内网的 VPN；在外网无法凭此访问内网服务。

## 新增公开来源

以下 6 个配置在 2026-10-09 接入检查时均能下载、包含非空 YAML 节点列表，且对应配置文件最近 24 小时内有提交更新。来源的自动更新时间由各项目控制，本仓库仍在每天北京时间 08:00 拉取和重新分类。

| 项目 | 最新分支配置文件 |
|---|---|
| [BestClash](https://github.com/PuddinCat/BestClash) | `main/proxies.yaml` |
| [Au1rxx/free-vpn-subscriptions](https://github.com/Au1rxx/free-vpn-subscriptions) | `main/output/clash.yaml` |
| [anaer/Sub](https://github.com/anaer/Sub) | `main/clash.yaml` |
| [AutoMergePublicNodes](https://github.com/chengaopan/AutoMergePublicNodes) | `master/list.yml` |
| [V2RayAggregator](https://github.com/mahdibland/V2RayAggregator) | `master/Eternity.yml` |
| [zhuhaiuk/free-nodes](https://github.com/zhuhaiuk/free-nodes) | `main/clash_config.yaml` |

原订阅的 a1 已从固定历史提交地址改为 Gist 最新版本地址；a7 改为 GitHub 原始配置地址。新来源的节点仍需通过本仓库的连通性与网站复测，来源自带的速度或地区标签不作为入选依据。

每次报告列出各来源的下载数量、新增唯一节点、重复数、跳过数、下载状态和内容指纹；每个入选节点记录全部匹配来源。新增唯一数按清单顺序计算，不是来源有效率或速度排名。

编辑 `节点来源.yaml` 的 `sources` 列表可添加来源，`id` 必须唯一，`url` 应是固定的 HTTPS YAML 地址；设 `enabled: false` 可停用。只读取来源节点，不导入外部配置的规则、分组、脚本或本地设置。长期失效、停止更新或只能提供日期文件的候选本次没有接入。

## 修改检测方式

入口和分阶段检测位于 `scripts/availability.py`，网页及 trace 的响应校验位于 `scripts/mobile_pilot.py`。工作流只安装 Mihomo，使用独立节点监听端口，不打开 TUN、不修改系统代理。旧下载测速脚本仅用于历史复现，当前工作流使用直接 HTTP 的 1 MB 快速采样及通过节点的 50 MB 复测。

综合、高速和非机房组均仅香港最多 30 个，其他地区不限制数量。高速组要求 20 秒内完整通过 50 MB；非机房组仍按独立出口去重。完整样本与各阶段分类继续保留在报告。定时触发可能延迟；GitHub 长时间无活动可能暂停定时任务。

## 节点名称与 IP 信誉

名称仅显示“地区·唯一标识 | 延迟 | Mbps | 住宅类型 | 纯净度”。延迟优先显示 Google/YouTube 样本响应中位数中的较慢值，标“网页”；没有两站可用测量时使用 HTTPS 204 中位值并明确标“204”；带宽由完整 50 MB（优先）或 1 MB 的 MiB/s 换算为 Mbps（× 8.388608），是下载采样值。未经确认的值显示未知；报告保留采样来源。唯一标识保证同地区节点不重名。

[ipapi.is 官方评分说明](https://ipapi.is/blog/abuser-score.html)提供网段滥用比例 `company.abuser_score`；显示的“网段纯净度”取 `100 × (1 − 比例)`，越高表示同网段未标记滥用的 IP 占比越高。这是明确标注的换算值，不是官方综合风控分，也不是单个 IP 的安全概率。`is_abuser=true` 另标“有滥用”，即使网段分数高也保留此提示。标记、数据来源及查询时间保存在 JSON 报告。

ISP 网络且 `is_datacenter=false` 标为“住宅候选”；移动网单独标注，机房优先于 ISP 类型。ip-api.com 的 `hosting=false` 只标“非机房”，不能证明住宅；缺字段保持“住宅未知”。原非机房组入选要求保留。

[免费 ipapi.is 账号](https://ipapi.is/free-tier.html)每日 1,000 IP 查询，完整检测标记需要 Key。将 Key 添加到[本仓库 Actions Secrets](https://github.com/hoooou/my_yml/settings/secrets/actions)，名称为 **IPAPI_IS_KEY**，不要写入配置或仓库。本流程只查 1 MB 通过的去重出口，每次最多 900 个，100 个一批；批量仍按 IP 计费。只用免费额度，收到鉴权或额度错误立即停止；重复手动运行可能耗完当日额度，剩余显示未知。Key 未配置时不请求此服务，订阅仍可正常生成。每日 full 和手动 repair 都支持查询；普通本地 repair 不刷新网络，需显式 `--refresh-ip-reputation`。

## 请求响应质量

网页测量侧重请求和响应速度，不启动浏览器，不把完整页面渲染作为门槛。每次使用独立连接，包含 DNS、代理建连、TLS、跳转及服务端等待；响应头耗时是近似 TTFB，不是纯服务器处理时间。收到响应头快但正文接收慢的节点也会被降级。Amazon最多读取64 KB，其余最多16 KB，实际样本字节数写入报告，不将小页面的字节/耗时算成带宽。带宽继续来自完整 1 MB/50 MB 下载。底层连接/读取超时分别 3/2 秒，5 秒是采样判定预算，并非强行中断系统调用的绝对时限。

三轮分别记录成功、超时、风控或慢响应；成功率、最慢/P95、延迟极差及响应头中位耗时写入 JSON。三轮样本的最近秩 P95 等于最大值，不能代表长期第 95 百分位；极差表示本轮波动，不是链路丢包率。超时的实际耗时参与尾延迟和波动，不只统计成功请求。国内站和 trace 仍各一次，不混入海外稳定性得分。

手动模式 **web-recheck** 只对订阅中仍有节点定义、已有 1 MB 快测通过的节点进行三轮海外请求复测，用一个 Actions 作业、8 个节点并行、每节点最多 5 个网站请求并发，不重跑 TCP、国内站、trace 或下载。逐节点海外复测时间单独记录，旧测量时间和下载结果保持原样；未复测的旧单轮样本不冒充稳定三轮结果。`repair` 同样只重建已有定义，完整历史报告不因订阅精简被删掉。重新获取被淘汰节点使用每日或手动 **full**，对全部来源按阶段检测。

## 指定网站必过与全量结果

必过网站：Google、YouTube、ChatGPT、Claude、Gemini、GitHub、Wikipedia、Reddit、X、Instagram、Telegram、Discord、Facebook。每站三轮全部通过才进入下载和候选选择；403、验证码、失败、慢响应、未测和仅trace通过均不符合要求。台湾／新加坡组也须满足13站，只放宽Google/YouTube的响应耗时。Amazon继续检测但不在必过清单；抖音停止检测，直连分流保留。

每次完整全量测量保存 Actions 的 **full-test-report** 存档7天，包含来源、节点结果、每站状态、HTTP响应和失败原因统计。没有合格节点时检测报告仍保存，但发布步骤拒绝覆盖旧订阅；旧订阅不代表已经通过新13站门槛。手动全量运行另保存 **amazon-page-diagnostics**，从三个已发布节点检查Amazon不同样本长度的识别结果，不能以诊断代替入选检测。

Amazon诊断发现：部分云端响应为HTTP200且包含正常首页标题，但没有Content-Type头。现允许仅Amazon在类型头缺失时，凭DOCTYPE、HTML/head结构和Amazon标题确认HTML；明确非HTML类型、验证码、错误页面及超时仍不通过，不通过HTTP200本身放行。识别依据写入每次请求结果，仅Amazon采样上限扩大到64 KB，其余仍16 KB；时间预算不变。
