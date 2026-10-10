# Clash 节点优选

`聚合配置.yaml` 是原订阅源和分流规则的输入，`节点来源.yaml` 是新增的公开免费来源清单；`优选配置.yaml` 是自动筛选后可直接导入的完整配置，适用于 Clash Meta / Mihomo 客户端。

## 使用

在客户端中添加远程配置：

```
https://raw.githubusercontent.com/hoooou/my_yml/main/%E4%BC%98%E9%80%89%E9%85%8D%E7%BD%AE.yaml
```

将客户端的远程配置刷新间隔设为 24 小时。GitHub 更新文件后，客户端仍需要刷新才能加载新节点。

手机只保留 **9 个分组**，默认在“🚀 全局选择”使用“⭐ 综合优选”。刷新原订阅即可生效。

| 分组 | 用途 |
|---|---|
| 🚀 全局选择 | 选择当前使用哪类节点，默认综合优选 |
| ⭐ 综合优选 | 优先选完整通过 1 MB 下载的节点，按网站覆盖、延迟和采样速度排序；无下载通过结果时回退到其他候选 |
| ⚡ 高速下载 | 仅从 1 MB 快测通过的节点继续完整下载 50 MB，按此次速度取前 30 个 |
| 🏠 非机房 IP | 通过快速下载且明确不是机房的独立出口，最多 30 个 |
| 🌍 按地区选择 | 国家名称排在节点开头，每地区优选最多 30 个，集中在同一个列表 |
| 📶 TCP通 | 已测国内入口能连接，供手机对照；不保证所有网站可用 |
| ⛔ TCP不通 | 已测国内入口连接失败，供手机检查是否存在不同线路结果 |
| 🔎 TCP未验证 | 204 未通过而未提交 TCP、UDP 协议或接口无可靠结果，不能理解为不通 |
| 🎯 全部节点 | 全部内核可解析且手机兼容的节点，供手动对照 |

合并原来的 204、trace、三站及单网站分组；不再为每个国家生成一个独立组。JSON 报告保留逐节点、逐网站完整结果，Markdown 展示网站覆盖和节点概要。检测与域名分流共用审核后的清单，见 `scripts/site_catalog.py`。

## 每日更新

GitHub Actions 的“每日节点连通性分类”每天北京时间 **08:00 开始**，也支持手动触发。四个免费标准 Actions 分片并行，每片最多同时处理 16 个节点；同一节点按下面的顺序过关，不同节点可以同时处于不同阶段，不等待全量上一阶段结束。

1. 获取原配置 11 个来源和新增 6 个公开来源的最新节点，按连接配置去重；不同密码、UUID、协议或传输参数保留。内核不支持或包含非法控制字符的节点在报告记录，不写入手机订阅。
2. **先批量检查 HTTPS 204，独立请求三轮**：`https://connectivitycheck.gstatic.com/generate_204`。三次均返回无正文的 204 才继续；记录每轮延迟、中位数和最大值。不通过的节点在名称注明“204未通过”，放在“TCP未验证”和“全部节点”中，不伪造国内入口失败。
3. **再进行国内 TCPing**：仅对 204 通过且支持 TCP 的主机/端口调用小小 API，一入口一次。共享入口只提交一次，不同凭据的节点独立检查 204 和后续访问。四片合计约不超过 5 次请求/秒。明确连接失败记为“不通”，接口限流、异常、超时或目标不匹配记为“未验证”。UDP 的 TCP 阶段不适用，保留供手机对照。
4. **再检查 26 个海外网站、14 个国内网站和两个 trace，各一次**。海外为原十站，以及 Telegram、Discord、Facebook、WhatsApp、Netflix、DisneyPlus、Spotify、TikTok、Twitch、Amazon、Bing、Steam、StackOverflow、HuggingFace、Perplexity、Cursor；国内为百度、哔哩哔哩、抖音、微信、淘宝、京东、知乎、微博、腾讯视频、爱奇艺、网易云音乐、小红书、DeepSeek、Gitee。每节点最多 **5 个请求并发**，地址增加时分批执行。参考 [EDT 页面](https://edt-pages.github.io/admin/) 的国内/国际覆盖思路，但验证首页 HTML 和站点标识，不把图标响应当作功能可用。仅读取前 16 KB，要求正确域名、200、HTML；最多跟随两次 HTTPS 跳转，仅允许入口域名和对应 www/非 www 域名；其他跨域跳转、403/412/429/444/451、验证码或风控记为需复核。脚本的 captcha 开关不会误判为验证码。请求使用项目 bot 标识，符合 [Wikimedia 的要求](https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Foundation_User-Agent_Policy)。trace 必须匹配预期域名、公网出口、地区和 HTTPS；通过只说明连通，不证明登录、对话或视频播放可用。海外排名仅统计 26 个海外页面，不要求全部通过；国内站经当前节点回访，仅供对照，不代表手机直连或移动实测，不参与海外评分，也不能单独触发下载。
5. **最后 Cloudflare 快速下载一次**：TCP 通且至少一个海外网页或 trace 通过后，通过同一个节点访问 [官方 1 MB 下载地址](https://speed.cloudflare.com/__down?bytes=1000000)。请求禁止重定向和压缩，响应状态、类型、声明长度及完整字节数都匹配才通过。读取超时 1 秒，采样预算 6 秒；达到预算就停止读取，底层建连/读取还可能等待其自身超时。记录完整 1 MB 的速度及耗时，包含 TLS 与首字节等待，属于快速采样速度，不是峰值带宽。
6. **增加 50 MB 高速下载复测**：只对第 5 步完整通过 1 MB 的节点，下载 [Cloudflare 50 MB 文件](https://speed.cloudflare.com/__down?bytes=50000000)一次。单次预算 **30 秒**、读取超时 1 秒，每个 Actions 分片最多 **2 个同时下载**（四片总共最多 8 个），减少大文件测试相互抢占带宽。要求完整 50,000,000 字节、响应状态/类型/长度匹配且在预算内完成；半截下载、超时或连接失败均不入选。单独的“⚡ 高速下载”组按这次 50 MB 实测速度从高到低取 **前 30 个**，不足 30 个不补失败节点。速度包含建连和首字节等待，仍是 GitHub 云端测量。节点名称优先显示 `50M` 速度；未通过大文件时显示原 `1M` 快测速度。
7. 排名先选择完整下载通过，再比较网页通过项数、三项连通通过数、204 中位延迟、下载速度及 TCP 延迟。地区组及非机房组只从下载通过的节点选取；地区取实际 trace 出口地区，各最多 30 个；非机房要求明确 `hosting=false`、不同 trace 未发现出口不一致，并按独立出口 IP 最多取 30 个。未确认 IP 类型不进入非机房组。
8. 四片结果全部合并，检查批次、完整覆盖、各阶段顺序和轮数、下载完整性。缺片或漏测拒绝发布。Mihomo 最终配置校验通过后，更新原订阅和 `连通性报告.json/md`。分片临时文件保留 1 天。

Cloudflare 官方测速引擎使用 `https://speed.cloudflare.com/__down`，`bytes` 参数指定字节数，见[官方项目](https://github.com/cloudflare/speedtest)。本流程先用 1,000,000 字节（1 MB），通过后再用 50,000,000 字节（50 MB），无需安装或调用 clash-speedtest。

探测服务：

| 服务 | 当前用途 |
|---|---|
| [小小 API](https://xxapi.cn/doc/tcping) | 国内 TCPing 自动分类；运营商未公开，不能称为移动线路实测 |
| [ITDOG](https://www.itdog.cn/batch_tcping/) | 网页人工对照；未接入可用的全量自动接口 |
| [TCPING.CN](https://www.tcping.cn/tcping) | 网页人工对照；自动接口要求人机验证时跳过 |

每轮记录另外两家服务状态，不宣称三家都完成自动探测，不绕过人机验证。TCP 结果仅代表所测探测点，海外访问和下载速度来自 GitHub 云端，仍需手机对照中国移动的实际体验。

发布前检查所有解码字段，剔除非法控制字符，避免 FlClash 重新生成配置后报 `control characters are not allowed`。正常中文和图标保留。手动触发选择 `repair` 仅修复已有配置，不进行网络检测，保留原测量时间、原轮数和原下载设置；每日任务及默认 `full` 执行最新分阶段流程。

`测速报告.*`、`移动小测报告.*` 是历史结果，以 `连通性报告.*` 为准。手机订阅地址保留；所有来源失效或配置不能校验时保留旧订阅。

## 手机分流与 DNS

匹配顺序：局域网和私有域名直连 → 保留广告拦截 → 明确的海外服务走“🚀 全局选择” → 国内服务直连 → 个人域名例外 → 应用、Apple/iCloud、代理/GFW/国内维护规则集 → 中国 IP 直连 → 未匹配流量走全局选择。海外 AI、影音、社交和开发服务包含常用 API、登录、静态资源及 CDN 域名，检测和分流共用清单。保留 Office、OneDrive、SharePoint 等个人域名直连选择；Cursor 改为代理，服务规则优先于应用进程直连，移除 Tencent/元宝模糊关键词直连，启用原来未引用的 GFW 列表。没有增加应用策略组。

国内 DNS 和节点域名使用阿里/腾讯 DoH，引导 DNS 为 `223.5.5.5` 与 `119.29.29.29`，移除旧的 `192.168.70.49`。海外 DNS 查询通过全局选择的节点访问加密 DNS；独立节点域名解析器避免代理与 DNS 互相依赖。保留原 IPv6 选择，加入局域网及 Windows 网络检查域名的 fake-IP 排除。依据 [Mihomo DNS 文档](https://wiki.metacubex.one/config/dns/)和[规则集合文档](https://wiki.metacubex.one/config/rule-providers/)；服务域名内置，维护规则集继续每天更新。

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

地区最多 30 个及非机房独立出口最多 30 个只限制优选分组，不影响全部样本与对照分类。定时触发可能延迟；GitHub 长时间无活动可能暂停定时任务。
