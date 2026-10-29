# Clash / v2rayN 节点优选与检测说明

每 6 小时（北京时间 05:00、11:00、17:00、23:00），使用免费 GitHub Actions 获取全部订阅，去重后检测，生成适用于 FlClash、Clash Meta / Mihomo 的完整配置。目标是入口可达、请求响应快、稳定且上下行良好的节点。全局组保留手动选择、默认综合优选，其他分组自动按延迟选择节点；出口IP变化本身不作为淘汰理由。

本文件是唯一维护的 Markdown：使用方法、当前规则、来源、诊断结论及最新检测结果均集中在这里。历史方案、已被替代的门槛和重复报告已经合并清理；原记录仍可从 Git 历史追溯。

[最新检测摘要](#节点检测报告) · [最新阶段及网站统计JSON](最新检测.json) · [当前订阅统计JSON](连通性报告.json) · [GitHub Actions](https://github.com/hoooou/my_yml/actions)

## 使用与分组

在客户端添加远程配置，继续使用原订阅链接：

```text
https://raw.githubusercontent.com/hoooou/my_yml/main/%E4%BC%98%E9%80%89%E9%85%8D%E7%BD%AE.yaml
```

建议24小时刷新一次；手动任务更新后也可以立即刷新。FlClash 使用规则模式并确保流量进入 VPN/TUN；Clash Verge 的应用设置或订阅脚本可能覆盖配置，排查时以核心实际加载的配置为准。

### v2rayN 原生节点订阅

```text
https://raw.githubusercontent.com/hoooou/my_yml/main/v2rayN.txt
```

适用于已核对的v2rayN 7.24.4。在订阅分组中添加上述地址，关闭订阅转换，更新订阅后每个节点独立显示在主列表，可单独选择、编辑和测速。旧的`v2rayN.yaml`是整份Custom配置，已替换；已有旧订阅的用户需要把地址改为`v2rayN.txt`。

使用该版本官方支持的`v2rayn://`原生节点格式（ConfigVersion=4），保留HTTP、Trojan、VLESS等节点的实际地址、端口、认证、TLS/SNI、WS、XHTTP和HTTP伪装传输。当前54个节点完整导出，49个HTTP节点仍是HTTP，不冒充SOCKS、不包成一份Custom。设置Xray核心、关闭节点Mux，其他协议将按实际支持导出；遇到不能完整转换的协议或字段（例如WS自定义User-Agent），该节点只从v2rayN订阅中略过、Clash配置照常保留，日志和报告`v2rayn_skipped`列出名称与原因，不会为了一个节点整轮不发布，也不会删掉字段后冒充原节点。[7.24.4官方原生格式](https://github.com/2dust/v2rayN/blob/7.24.4/v2rayN/ServiceLib/Handler/Fmt/InnerFmt.cs) · [HTTP原生导入支持](https://github.com/2dust/v2rayN/blob/7.24.4/v2rayN/ServiceLib/Handler/ConfigHandler.cs)

每轮与Clash订阅使用同一轮合格节点一同发布。原生节点订阅只携带节点参数及测量名称，不携带Clash的url-test分组、进程规则或内网DNS；v2rayN使用自己的路由和DNS设置。内网域名如需直连和私有DNS，应在v2rayN另行设置；不同核心的兼容性校验不能替代本地网络实测。

### 链式配置（前置 → 美国落地）

```text
https://raw.githubusercontent.com/hoooou/my_yml/main/%E9%93%BE%E5%BC%8F%E9%85%8D%E7%BD%AE.yaml
```

与`优选配置.yaml`同源、独立发布，**不影响原配置**。区别只有一处：所有落地节点通过`dialer-proxy`挂到`🌉 前置`组，前置从同一轮免费池中筛出，不按地区筛：国内 TCP 能过的节点都进前置轨道，再由实测门槛决定去留。

| 前置条件 | 说明 |
|---|---|
| 国内 TCP 可达 | `xxapi` 探测点从国内发起，单次 TCP 成功 |
| 上行预检 | 前置自己的上传预检通过 |
| TLS 无异常 | 前置自己的 TLS 探测无异常 |
| 回国 / 出国 | 国内与海外目标都能连通 |
| 10MB | 前置自己跑完 10MB 下载（不跑 100MB） |

排序：前置自己的 10MB 下载速度 → 国内 TCP 延迟。不按地区筛，美国节点同样可以当前置；前置少于 3 个时退回单跳，文件头会注明原因。

落地侧（`后置配置.yaml`）：预检、必过站点、应用 TLS、1MB、3MB、上行预检、100MB 双目标全部通过，稳定性有记录时也要通过；只收 TCP 类型，hysteria2／tuic／wireguard 不收（前置转发不了 UDP），并排除 Cloudflare。名字按出口国家重新编号（`美国01|…`），链式配置的地区组按这个前缀筛。

已知限制：链式必然增加延迟；前置只测自己这一段（回国、出国、TLS、10MB），不针对某个落地做定向验证；`v2rayN.txt`不挂链。

| 分组 | 条件与用途 |
|---|---|
| 🚀 全局选择 | 选择分组或直接手动选择任一已发布节点（含免测节点）；默认综合优选 |
| ⭐ 综合优选 | 入口、逐站可达、应用SSL及1MB通过，持续稳定性≥90%；综合组取本轮≥99%（不足时取最高成功率档）且结束已恢复的节点，多轮历史不稳者不进综合组 |
| 🚄 中速下载 | 已入选合格池内完整通过5MB快测的节点，包含台湾／新加坡地区池 |
| ⚡ 高速下载 | 综合合格池内Cloudflare和DataPacket双100MB都完整通过；取较慢一次速度排序 |
| 🏠 非机房 IP | 综合合格池内明确hosting=false、没有已发现的出口矛盾；按独立出口IP去重 |
| 🌏 台湾／新加坡 | trace确认TW/SG；入口、必过网站/API、SSL、1MB和稳定性仍须通过，上传速度用于分级 |
| 🍓 小草莓（免测） | 用户指定订阅在最终生成时追加，保留原名称；独立select手动分组，不测速、不淘汰、不进入各优选组 |

香港整体最多30个，非香港不限数量；公共订阅输入节点仍按阶段接受检测。中速／高速组保留所有满足对应条件的已入选节点，不另外取前30。组间可重叠，数量不能相加；空组显示REJECT，不用失败节点补足。TCP通／不通／未验证、全部节点、按地区选择等诊断组已移除。淘汰节点的定义和凭据不写入订阅。

小草莓来源是用户明确授权的免测例外，通过Actions Secret `UNTESTED_SUBSCRIPTION_URL`配置地址，不将带token的地址写入仓库。只在全部筛选完成后获取并追加`proxies`，不接受来源自己的规则或DNS；节点名称加“🍓 ”前缀，不伪造延迟、带宽、住宅或纯净度。与已入选定义相同的节点共用，来源内重复去重；这些节点同时进入v2rayN原生汇总订阅。只做格式和最终核心配置校验，不连接节点进行探测；获取失败时本轮不含免测节点、检测入选节点照常发布（报告注明），报告单列免测数量，不计入任何检查通过数。该组使用select且没有自动延迟检测，全局默认仍为综合优选。

全局组使用select、default-selected为综合优选；其他组使用url-test，切换容差50ms。HTTPS 200（claude.ai/cdn-cgi/trace）延迟检查每300秒一次、5秒超时、期望200、关闭lazy。客户端支持时可手动固定节点，节点不可用时可能自动切换出口。[Mihomo分组字段](https://wiki.metacubex.one/config/proxy-groups/)

节点名称：`美国01|120ms|85Mbps|机房|纯净度99.2%`。延迟使用实际请求中位数；带宽优先双100MB较低值，再用通过的5MB或1MB。第四段按出口 IP 的类型显示`机房`／`住宅`／`移动网络`／`未知`：`机房`是 hosting=true 的数据中心地址，`住宅`要求 hosting=false 且运营商类型为 isp，`移动网络`是 is_mobile，其余一律`未知`——**未知不等于住宅**。住宅也不保证快速或稳定。

## 当前筛选流程

四个免费标准Actions分片并行，每片最多处理16个节点；同一节点按前置条件顺序检测，不同节点处于不同阶段。网站、下载与持续稳定性使用不同运行机器，避免同一测速机器上的带宽争抢。每天重新参测，不永久拉黑某协议或某地区。

| 顺序 | 环节 | 当前要求及失败影响 |
|---|---|---|
| 0 | 来源获取／去重／配置解析 | 原配置11个来源加6个新增来源；按完整连接配置去重，不合并不同凭据或传输参数。剔除不支持或含非法控制字符的节点 |
| 1 | 双HTTPS 204各三轮 | Google `https://connectivitycheck.gstatic.com/generate_204`及Cloudflare `https://cp.cloudflare.com/generate_204`，交替顺序，各三次无正文204、严格TLS；两者全部通过才进入国内TCP。任一失败跳过后续入口检测；报告分别列两个目标和联合门槛，节点名称延迟仍取Google请求 |
| 2 | 国内入口TCPing | 小小API，一入口一次，共享入口去重；四片总请求约≤5次/秒。明确连接失败淘汰，接口异常保持未验证；UDP不适用TCP，正式流程不凭云端204放行 |
| 3 | 3MB上行预检 | `https://speed.cloudflare.com/__up?bytes=3000000`，随机合成3,000,000字节、6秒完整HTTP请求预算，严格证书校验；每片同时一个。速度不达标继续网站及观察，TLS异常仍淘汰 |
| 4 | 海外网页／API／trace | 25个海外页面及ChatGPT API各三轮，两个trace单轮；每节点最多5个请求并发。指定必过目标见下文；任何网站／API／trace出现TLS异常（含非必过网站）均淘汰，普通连接超时按既有规则处理 |
| 5 | 应用SSL | chatgpt.com、android.chat.openai.com、auth.openai.com、cdn.oaistatic.com各至少两次成功独立TLS；仅一次普通连接失败可补测一次。单次5秒、TLS≥1.2，信任链、域名、有效期必须正常 |
| 6 | Cloudflare 1MB快测 | `https://speed.cloudflare.com/__down?bytes=1000000`，6秒内完整接收；所有入选节点必过 |
| 补充 | FAST API／Netflix CDN | 1MB通过后通过urlCount=3取得最多三个不同CDN主机，依次各下载1MB、各限6秒。普通失败只报告；明确证书错误淘汰 |
| 7 | Cloudflare 5MB快测 | `https://speed.cloudflare.com/__down?bytes=5000000`，10秒完整接收，每片最多4个并发；通过才进中速组，失败仍可继续100MB |
| 8a | Cloudflare 100MB | `https://speed.cloudflare.com/__down?bytes=100000000`，20秒完整接收，带Referer: https://speed.cloudflare.com/ |
| 8b | DataPacket 100MB | `http://hkg.download.datapacket.com/100mb.bin`，20秒完整接收；同节点两目标顺序测试，首轮失败也测第二轮，每片最多2节点同时测。两目标都过才进高速组 |
| 9 | 最终上行及负载 | 复用3MB预检，再对Cloudflare上传5MB两轮、各10秒、间隔20秒；预检速度失败也完成两轮。速率、重复一致性及上传中204用于分级，TLS异常仍淘汰 |
| 10 | 上传后SSL | 四个应用域名再次各两轮严格TLS检查 |
| 并行 | 持续稳定性 | TCP通过后独立观察，3MB预检不阻挡观察；每轮结束随机等待3～10秒，不重叠、不限定20轮，每节点至少10分钟，每片最多8节点；排队可能延后实际间隔。持续到主流程结束，再补每节点一轮且满足最短观察时长 |
| 11 | 合并／分组／配置校验 | 核对同轮、所有分片和节点覆盖、各项原始证据及轮数；缺片、漏测、对照异常拒绝更新订阅。最终Mihomo校验通过才发布配置 |

204和网站的响应时间、trace、完整上下行以及证书证据分别判断，不能相互替代。上行6秒包含建连与响应，3MB对应约4Mbps端到端采样下限；客户端完整提交且预期HTTP响应正常，不是逐字节服务器收据。下载要求HTTP200、正确目标／类型／声明长度、无压缩／跳转及完整字节数；半截下载不能当作通过。小文件速度包含握手和首字节等待，不是持续峰值带宽。[Cloudflare官方测速引擎](https://github.com/cloudflare/speedtest)

稳定性成功率≥90%，排名考虑成功率、最长连续失败、每站成功请求P95／P99、四分位距和上下行表现。失败通过成功率单独处罚，不混入延迟分位数；小样本P99接近最大值，仅作参考。明确证书校验错误始终淘汰，不因偶尔恢复抹去失败，也不要求ChatGPT trace出口IP固定。旧五轮全过／额外最大延迟硬门槛已被此方案替代；不能把旧记录追认为新的持续采样。

新版Google／YouTube成功响应耗时用于排序，不再额外叠加1.5/3/1.5秒硬门槛；请求本身仍有有界超时，各地区都不放宽证书和逐站可达要求。CF／Reddit确认例外可以认可可达，真实响应速度只用正常页面。5MB／100MB失败不淘汰普通池，只影响对应下载分组。

### 稳定性优先策略（第2版）

3MB/6秒与两轮5MB上行继续实测，速度不决定普通节点资格；全部大样本上传未完成时补一次64KB/6秒请求，确认基本上行可用，不能放行完全无法提交数据的节点。1MB基础下载仍必过，5MB/双100MB继续决定下载分组。新版下载使用curl总时限，取消独立1秒读取超时；完整字节、目标、类型和严格TLS要求保留。

上行两轮之间至少等待20秒，等待期间释放传输工作线程，供其他节点测量；上传并发仍为4，不通过增加同时传输来争抢测速带宽。稳定性观察随主流程结束，运行保护上限115分钟，任务上限120分钟；这些是异常终止保护，不是每节点必须测满的时长。

持续观察第5版从国内TCP通过后启动，每节点至少10分钟，不以20轮为上限。每轮独立请求Google204、Google、YouTube、ChatGPT trace及Android TLS，另通过节点独占的HTTPS连接池请求Google204；前置失败不跳过其他目标。连接池可能重建连接，不声称保持一条始终不断开的TCP连接，也不模拟登录会话。成功轮次是多个请求的联合结果，请求成功/失败另记；排名考虑成功率、连续失败、恢复耗时、历史表现、每站P95和波动。少于100个成功样本不展示P99。

利用现有每6小时（北京时间05/11/17/23点）运行积累近7天精简记录，按完整连接参数识别节点；旧版测量、仅重建或修复发布不增加新观测。记录样本数、时长、昼夜P95及变化；没有晚间或跨日证据标为待积累，不把云端成绩称为本地移动网络成绩。普通节点保留线仍为90%；综合组优先99%及以上且结束已恢复的节点，不足99%时只取本轮最高成功率档；至少两轮历史且历史成功率不足99%或入口曾失败的节点不进入综合组。下载组仍可保留满足基本资格的节点，不新增诊断分组。

新增YouTube页面实际JS/CSS/图片资源诊断和ChatGPT API响应完整性检查。普通资源失败先观察，不作为未经对照验证的新淘汰项，任何TLS异常仍淘汰；未测试真实视频或登录后对话。

另从原始公共节点提取HTTP(S)/SOCKS上游候选，放在Actions的edgetunnel-candidates附件（1天）；不受国内TCP门槛影响、不混入免测来源、不写进现有订阅、不冒充原生ProxyIP。尚无实际Worker链路证据，这部分标为未验证。

### 网站、API及访问限制

逐站均需通过（三轮至少两次认可可达，余下一次只能是普通连接失败）：Google、YouTube、ChatGPT、Gemini、GitHub、Wikipedia、Reddit、X、Instagram、Telegram、Discord、Facebook、ChatGPT API。Claude首页不测试，只要求`https://claude.ai/cdn-cgi/trace`；ChatGPT trace为`https://chatgpt.com/cdn-cgi/trace`。trace首次普通连接失败允许复测一次且必须成功，仍要求预期HTTPS主机、公网IP及地区结构，只说明接口可达。

其他页面：Amazon、Bing、Cursor、Disney+、Hugging Face、Netflix、Perplexity、Spotify、Stack Overflow、Steam、TikTok、Twitch、WhatsApp。它们参与覆盖／质量和证书检查，但单站失败不是独立的必过淘汰条件。TikTok保持首页原逻辑；`/cdn-cgi/trace`经云端验证均跳到/404，因此未接入。抖音和普通国产网页不参加每日逐节点测试；国产应用走DIRECT，经海外节点访问国产网站的成绩不能代表手机直连体验。检测与分流共用`site_catalog.py`清单，范围参考[EDT](https://edt-pages.github.io/admin/)。

正常网页要求正确HTTPS主机、200、HTML及站点特征；首响应预算3秒、正文采样总预算5秒。一般正文上限16KiB，Amazon64KiB；Reddit 401/403可读取至512KiB以定位可见登录提示。使用桌面Chrome兼容请求头，不固定Bot UA；普通HTTPS跳转最多两次，限制到入口域名及对应www／非www；Gemini可有限经过Google /sorry/index后返回正常Gemini页面，最多四次，最终请求首响应仍≤3秒、累计总耗时≤5秒，不把302本身记为通过。

明确的Cloudflare人机验证在所有已测网页上认可可达，依据预期HTTPS主机和`cf-mitigated: challenge`等已确认信号；普通403、server=cloudflare或脚本中出现captcha都不足以放行。Reddit明确要求登录也认可可达，保留原401/403及可见证据，不把普通安全拒绝误当登录提示。新版三轮只允许一次普通连接失败，另外两次必须认可可达；HTTP拦截、错误内容或TLS异常不能使用该例外。人机验证和登录提示不算正常页面速度、登录／对话／播放成功。[Cloudflare验证页说明](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/)

ChatGPT API：`https://api.openai.com/compliance/cookie_requirements`。要求预期地址、HTTP200、JSON且cookie_consent_required为布尔值、无实际error；unsupported_country记录地区限制。这个接口不是ChatGPT会话检测，缺少地区错误也不能直接算通过。认证错误、跳转、结构变化、接口失效、超时、证书错误分别保存；解析规则不能仅从任意同名字段、country或最后HTTP200推断解锁。

### FAST补测

FAST官方客户端使用`api.fast.com/netflix/speedtest/v2`获取Netflix测速CDN，本项目使用公开浏览器token、HTTPS、urlCount=3。接口预算5秒、正文≤64KiB、禁止自动跳转；仅接受443端口的HTTPS `*.nflxvideo.net`及合法/speedtest基址或range路径。沿用[官方客户端](https://fast.com/app-0bffe1.js)的范围拼接方式，保留签名仅在内存，下载`/speedtest/range/0-999999`。

最多三个不同主机，顺序各测1MB、各6秒；API给不足三个时仍测有效目标，整体记未知，不重复凑数。三个都完整通过才记FAST通过，分别记录目标地区、耗时、字节及Mbps，汇总成功目标中位数和范围。不同主机不保证不同物理服务器或地区。API获取和实际CDN下载分别统计，普通失败不改变综合／地区门槛，不替代Cloudflare/DataPacket，不修改节点名或分组；明确证书错误仍淘汰。[FAST官方说明](https://fast.com/)

## 分流、内网DNS与IP标签

私有内网域名及其子域名优先DIRECT，nameserver-policy指向内网DNS并排除fake-IP（域名与DNS地址只写在 `scripts/routing.py` 配置中）。开启direct-nameserver-follow-policy，防止直连解析改用公共DNS。使用精确域名后缀，不依赖模糊关键词；配置随订阅生成，无需Clash Verge本地覆写。私有DNS只在对应内网或可到达内网的VPN下可用。

匹配顺序：内网／局域网直连 → 广告规则 → 个人进程例外 → 应用进程 → 应用域名兜底 → 明确海外服务 → 国内服务 → 个人域名例外及维护规则集 → 中国IP直连 → 未匹配走全局。保留Office、OneDrive、SharePoint个人直连选择；Cursor及相关域名代理，取消Tencent／元宝模糊关键词直连，并使用GFW列表。没有额外应用策略组。

| 路由 | 应用 |
|---|---|
| 指定直连 | 微信、微博、美团／大众点评、拼多多、京东、高德地图、企业微信、向日葵、腾讯会议 |
| 补充直连 | QQ／TIM、支付宝、淘宝、哔哩哔哩、抖音、网易云音乐、小红书 |
| 指定代理 | X／Twitter、Google Play、YouTube、Threads |
| 补充代理 | Telegram、Discord、Instagram、ChatGPT、Claude、Gemini、Cursor |

find-process-mode: strict按需识别；Android用完整包名，macOS／Windows用实际可执行名称，不使用macOS bundle ID。个人PROCESS-NAME／PATH／正则／通配符优先保留，浏览器、Python、Node、Git和通用Helper不整进程固定路由。未识别进程时回退域名规则；微信内打开海外链接仍按微信直连选择，内网和局域网优先级更高。

Google Play包括com.android.vending、com.google.android.gms、com.google.android.gsf；服务和框架的其他Google流量也代理。采用com.tencent.wemeet.app、com.autonavi.minimap及com.oray.sunlogin等有官方商店证据的完整包名；不导入厂商前缀、不采用被注释条目，不把Surge的USER-AGENT／通配符原样当成Mihomo精确进程匹配。

进程名称采用人工审核快照，通过GitHub代码搜索交叉核对，不自动订阅外部清单的全部路由；Loyalsoldier等域名／IP维护规则仍按原方式刷新。补充了向日葵Desktop／Helper／Service、Windows WeChatAppEx.exe及Google服务框架。macOS指定别名已用独立客户端验证核心命中；Windows／Android是名称来源核对，不宣称所有客户端和应用版本都已实机验证。手机需要连接日志确认实际包名。

住宅／纯净度来自可选ipapi.is，GitHub Actions Secret设置IPAPI_IS_KEY，不放入聊天或文件。免费配额按服务账号当时限制使用，按独立出口去重查询，每轮预算900个IP；重建可保留既有元数据；未配置或限流保持未知。纯净度=100×(1−company.abuser_score的有效网段比例)，不是账号安全／节点可靠性的概率。无hosting／住宅证据不推断住宅，不用运营商名称替代类型判断；IP查询失败不伪造测量成功。

## 来源与维护入口

`聚合配置.yaml`为原订阅／规则输入，`节点来源.yaml`为新增公开清单；每天只读取外部proxies，不导入来源脚本、规则或客户端设置。按协议、入口、凭据及传输参数去重，每个节点保留匹配来源。原a1使用Gist最新版本、a7使用GitHub原始地址。最近两次成功发布中仍有定义但本轮来源缺失的节点可以作为待测候选，凭据保留、所有测量重新执行；来源全失败不能用历史候选掩盖。

| 新增来源 | 配置路径 |
|---|---|
| [BestClash](https://github.com/PuddinCat/BestClash) | main/proxies.yaml |
| [Au1rxx](https://github.com/Au1rxx/free-vpn-subscriptions) | main/output/clash.yaml |
| [anaer/Sub](https://github.com/anaer/Sub) | main/clash.yaml |
| [AutoMergePublicNodes](https://github.com/chengaopan/AutoMergePublicNodes) | master/list.yml |
| [V2RayAggregator](https://github.com/mahdibland/V2RayAggregator) | master/Eternity.yml |
| [zhuhaiuk](https://github.com/zhuhaiuk/free-nodes) | main/clash_config.yaml |

来源接入时已验证可下载／节点非空，但更新由来源项目控制，本仓库不保证来源全天可用。编辑sources时id唯一、固定HTTPS配置地址，enabled=false可停用；每轮记录抓取时间、状态、下载数量、独有新增、重复、跳过及指纹。新增数按清单顺序归因，不是来源质量排名。

| 入口／代码 | 用途 |
|---|---|
| 每日节点连通性分类 / full | 每6小时或手动重新获取所有来源；四片前置、四片网站／下载、独立持续观察及最终上传、合并发布 |
| repair | 按已有原始证据重建规则／分组；不是全量重测，不伪造新时间或旧下载轮数 |
| web／medium／stability／uplink-recheck | 已发布池相应专项复测，保留其他项原测量；新版独立稳定性至少观察10分钟 |
| publish-retry | 复用指定完整且仍可取得的同轮存档恢复发布，不重新测速，不复用不同节点原始记录 |
| 补充服务小样本验证 | 最多4个当前节点、前后直连对照，验证ChatGPT API／FAST，不发布订阅 |
| 其他只读诊断 | Claude、网站、上传、持续稳定性、已发布节点、异常阶段以及Hysteria2；不改变订阅 |
| availability.py / mobile_pilot.py | 阶段编排、必过和地区池／网页、API、trace分类 |
| site_catalog.py / app_catalog.py | 共享服务域名及审核后的进程清单 |
| detection_report.py / latest_report.py | 实测展示及README最新记录；无候选也更新报告 |
| attempt_report.py / publish_subscription.py | 存档全量原始记录及匿名发布；订阅与检测报告分别保护 |

正式节点请求只在GitHub Actions进行，内核独立端口，不开TUN、不改本机代理。提交使用github-actions[bot]或仓库所有者的noreply地址，避免实名。配置含非法控制字符时剔除对应节点，保留合法中文／图标，防止FlClash报control characters are not allowed。

## 如何看报告

本文件自动报告区只保留最新一次全量／专项检测，包含来源与解析数量、每个阶段的实测／通过／失败／未验证／跳过及主要原因、各网站拦截数、入选表现和测量时间。每个FAST目标、两个100MB目标分别列行。未执行阶段明确显示原因，不能把跳过当失败或补造成功。全失败的必过网站会突出提醒复核检测器和响应。

`最新检测.json`是精简阶段／网站／来源元数据，保留全部失败／跳过原因计数；每轮原始逐节点／逐请求记录是Actions的full-test-report附件，保留7天。`连通性报告.json`只保留当前订阅统计与入选节点索引，不含逐请求记录；原始证据只保存在Actions的full-test-report附件，自动复测按需读取并校验。附件保留7天，过期后需重新检测，不能用摘要替代证据。它与`优选配置.yaml`对应当前实际订阅；本轮零候选时它们保持原值，但README及最新检测JSON仍更新，说明旧订阅未满足本轮验证。任务缺片、对照异常或配置校验失败不能发布新节点；任务未完成时应看该次Actions日志，不能把旧报告说成新测量。

发布更新基于当前main，保留期间新增的代码和README手工说明，只替换自动报告区。较旧测量不能覆盖新结果；最终配置验证通过才允许更新订阅。定时任务可能延迟，GitHub长期无活动可能暂停定时流程。

## 已核查的问题与证据

以下保留旧文档的有效结论和云端证据，旧数量仅代表各自测量时刻，不作为当前门槛。

| 问题 | 已验证结论及限制 | 证据 |
|---|---|---|
| Claude首页零通过 | 228个网站候选／684次首页请求无正常通过；小样本含明确CF挑战和香港地区限制。已按用户要求移除首页，仅Claude trace；不把605次旧403全部追认为同一种原因 | [首页诊断](https://github.com/hoooou/my_yml/actions/runs/38041782487)、[复核](https://github.com/hoooou/my_yml/actions/runs/38042040394) |
| 入口故障随时间变化 | 曾失败TCP样本6个中4个仍不通、2个后续恢复；接口异常由27增206不能直接断言限流。不永久拉黑，异常保持未验证 | [淘汰复查](https://github.com/hoooou/my_yml/actions/runs/38042994214) |
| Hysteria2不能用TCPing替代 | 云端认证204与国内UDP是不同证据。原生QUIC初始包在一入口国内三轮回应，其他云端可用样本无国内回包；Salamander覆盖及国内完整协议验证不足。正式入口保持未知 | [原生包对照](https://github.com/hoooou/my_yml/actions/runs/38045518576) |
| 来源换单导致候选消失 | 61变41个节点时，移除49个中的39个定义已不在来源。已将最近两次成功订阅缺失项加入本轮重新测试，不复用旧成绩 | [来源变化](https://github.com/hoooou/my_yml/actions/runs/38108536766)、[旧新池复测](https://github.com/hoooou/my_yml/actions/runs/38149039366) |
| ChatGPT SSL及重连 | 四域名独立TLS对照当前41个36过、旧61个60过，无确认的证书校验错误；已加前后应用TLS。不能据此声称复现或解决手机Wi-Fi证书／应用固定问题 | [TLS对照](https://github.com/hoooou/my_yml/actions/runs/38150529771) |
| 五轮淘汰过多及历史混计 | 66个五轮只13全过，12发布；后来12复测10保留。曾混入历史失败造成12节点摘要55失败，已按本轮ID修正；五轮规则后续替换为15秒持续观察、成功率≥90% | [五轮](https://github.com/hoooou/my_yml/actions/runs/38162604697)、[内核对照](https://github.com/hoooou/my_yml/actions/runs/38164462674)、[复测](https://github.com/hoooou/my_yml/actions/runs/38172571705) |
| 持续观察HTTP节点集中中断 | 一轮168观察、68未过，53个HTTP样本集中开始失败。后续8个失败HTTP样本短时全过、持续后各探测均失败，冷启动及放宽建连未恢复；健康对照正常。支持当时真实中断，未证明永久故障或具体后端限额 | [阶段核查源运行](https://github.com/hoooou/my_yml/actions/runs/38183961292)、[持续对照](https://github.com/hoooou/my_yml/actions/runs/38202540313) |
| 3MB上传失败不是都带宽不足 | 同轮48失败：28超时、18TLS握手、1空响应、1接收错误；17已发完3MB但未完成响应。curl35握手失败不等同证书校验错误；完整发送不等同成功HTTP请求 | [对应完整运行](https://github.com/hoooou/my_yml/actions/runs/38183961292) |
| TikTok请求头／Gemini跳转误筛 | 110个TikTok403中小样本改Chrome UA可恢复；Gemini /sorry/index可以返回正常页，已受控跟随并分别计最终TTFB与累计预算；403仍不自动放行 | [原数据](https://github.com/hoooou/my_yml/actions/runs/38201527803)、[请求头及跳转对照](https://github.com/hoooou/my_yml/actions/runs/38208188024) |
| Reddit明确登录可达 | 两个原403样本三轮都确认可见登录提示，原16KiB／128KiB截断遗漏了约190KB处的提示；现在该类401/403上限512KiB，保留403和证据认可可达，旧89个无证据的403不批量追认 | [登录提示验证](https://github.com/hoooou/my_yml/actions/runs/38209420994) |
| 服务端点与FAST范围 | TikTok trace三个可用样本和直连均跳/404，取消该端点；FAST目标实为/speedtest基址，按官方客户端拼范围后成功；API与实际字节分别检查 | [结构核查](https://github.com/hoooou/my_yml/actions/runs/38212157289)、[单目标验证](https://github.com/hoooou/my_yml/actions/runs/38213158100) |
| 三目标FAST | 三个可连通节点各三个不同主机、9次1MB完整通过；中位速度4.31／4.43／2.76Mbps，含建连。第四节点前置超时，前后直连API目标不可确认，未将其算下载成功 | [三目标小测](https://github.com/hoooou/my_yml/actions/runs/38215561855) |
| 零候选时新报告缺失 | 最新运行5552去重、5549可解析，161进入网站阶段、Facebook0通过，因此后续SSL／下载／FAST均跳过。旧发布把新报告留在附件、仓库仍旧摘要；已改为报告独立更新，门槛不凭此放宽 | [本轮完整测量](https://github.com/hoooou/my_yml/actions/runs/38216070355) |

Hysteria2只读诊断使用在线且有UDP能力的国内探测点，DNS正对照正常才使用；每轮／每点独立生成原生QUIC初始包及连接ID，最多4个入口、40个任务、每秒最多一次接口请求，401/403/429停止。idcd未提供国内原始回包，因此回应只证明UDP可达，无回应保持未知，不上传认证密码或原生载荷。[Hysteria2协议](https://v2.hysteria.network/docs/developers/Protocol/)、[QUIC版本协商](https://datatracker.ietf.org/doc/html/rfc9000#section-6.3)、[idcd接口](https://www.idcd.com/v1/openapi.json)

国内TCP正式来源是[小小API](https://xxapi.cn/doc/tcping)，未公开运营商，不标“中国移动实测”；用户已本地对照认为有参考价值。[ITDOG](https://www.itdog.cn/batch_tcping/)和[TCPING.CN](https://www.tcping.cn/tcping)用于人工对照，未承诺全量自动、不限额或绕过验证。

### 解锁规格的取舍及尚未实施项

借鉴服务独立超时、有限并发、结构化证据和响应地址；不采用“403就是未解锁”“某地区字段就是解锁”“关闭SSL校验”“接口失败退回首页country就算成功”等乐观判定。参考版ChatGPT地区错误识别不足、FAST误当流媒体播放、Disney+递归找字段／地区回退、Netflix固定视频ID容易失效；这些都不能证明付费内容播放或登录后的完整会话。[参考实现](https://github.com/clash-verge-rev/clash-verge-rev/tree/27efaf3/crates/clash-verge-media-unlock)、[Netflix VPN说明](https://help.netflix.com/en/node/114701/)、[Requests证书验证](https://requests.readthedocs.io/en/stable/user/advanced/#ssl-cert-verification)

尚未实施：YouTube真实视频播放、登录后ChatGPT对话、账号或付费内容授权、额外国内TCP间隔复测、独立晚间加测、实际Worker链路验收、完整国内HY2认证。YouTube静态资源与7天历史已接入，新版数据从实际运行开始积累。旧六轮／五轮全过、50MB下载和1MB上传前置已被替换；新端点先诊断，不把检测器失效变成批量淘汰。

GitHub测量代表云端到节点再到网站的路径；国内TCP只补入口可达，不等于手机中国移动的上行／下行／首字节。短时高分不保证全天稳定，住宅／纯净度不替代性能。手机校准可固定8–12个节点，在同网络对Google／YouTube做三次并晚间复查，记录短名、时间与恢复情况；不用一次恢复抹去本轮失败，不开启自动切换来掩盖问题。

### Facebook／WhatsApp HTTP400请求头诊断

[云端同节点对照](https://github.com/hoooou/my_yml/actions/runs/38223465878)：两节点与直连共六组，原Chrome UA加默认请求头均三轮HTTP400；补齐浏览器文档导航头后均HTTP200和预期品牌网页，普通Chrome也正常。curl的HTTP/1.1与HTTP/2只用UA时仍400，因此不是仅换HTTP版本即可解决。已为两站补齐导航头，保留原HTTPS地址、页面标识、3秒首响应／5秒采样及SSL标准；普通400不当作通过，旧161个节点不凭此自动追认合格。原始Facebook470／483、WhatsApp469／483次请求是400，其余是连接异常，报告单列HTTP错误避免混同慢响应。已对全部日常目标完成原始／完整导航头对照，API和trace保持接口方式。

### 全部网站及接口请求头复查

[完整云端对照](https://github.com/hoooou/my_yml/actions/runs/38226619641)：两个当时204三轮通过的不同出口节点加GitHub直连，29个目标×两种请求头×三轮，共522次请求。每个目标交替测试原Chrome UA／默认头与完整浏览器文档导航头，最大5请求并发、同样的TLS、正文特征与3秒／5秒预算，前后204正常。另对出现差异的最多四个网页使用普通Chrome；未登录、未解验证码，未关闭证书校验。

| 目标 | 两节点及直连配对结果 | 当前处理 |
|---|---|---|
| Facebook／WhatsApp | 两种请求头分别0/3→3/3，三个环境一致；400变200正常页面，普通Chrome确认 | 两站生产请求补齐Accept、Accept-Language及普通导航字段；每条记录保留request_header_profile，仍必须正常页面且在预算内 |
| 其余20个海外页面 | 三个环境均3/3→3/3 | 未发现成批请求头兼容误筛，保留原方式，不把小样本外推为所有出口永久可用 |
| Reddit | 一节点2/3→2/3，各有一次连接失败；另节点及直连均3/3 | 保留逐轮真实异常与原登录／CF例外，未发现请求头带来改善 |
| ChatGPT | 一节点3/3→2/3，完整头多一次连接失败；其他环境均3/3 | 偶发连接失败不能推断导航头导致封禁；普通Chrome该样本仍可能遇CF挑战，保持既有可达策略 |
| Amazon | 两节点原／完整均0/3、HTTP202；直连均3/3 | 完整头未解决；202不作为正常首页，保持可选站及原分类，不宣称解锁或线路断开 |
| ChatGPT API／204／两个trace | 三个环境均3/3→3/3 | 不发送网页导航头，保持接口预期JSON／204／text trace验证 |

完整导航头本身不等于真实浏览器的TLS／HTTP指纹、脚本执行或登录状态。此次522次比较证明Meta两站存在已复现的请求头问题，不能证明所有站都需要同一组头。修正只影响未来真实测量，旧161个网站候选不凭请求头更改批量改判；需下一轮实际全量重新经过下载、上传及稳定性筛选。请求限制／HTTP错误、慢页面与连接异常已分别列出，防止把400／202误解释为带宽问题。首轮全站任务曾因旧样本当前204失败中止，后续改为从最多12个候选中当场核验三轮，再测两个当前可用样本，不用历史通过掩盖失效。

## 进程规则参考

2026-10-10使用已认证GitHub代码搜索，10组PROCESS-NAME关键词查询，针对性读取15仓库／16文件，非只按仓库名发现。固定版本链接保留溯源；镜像／相互借用不能视为独立实测，日期不保证当前应用版本已验证。只适配用户指定的精确进程名称，不自动跟随外部路由选择。

| 规则文件（固定版本） | 文件最近提交 | 参考价值与限制 |
|---|---|---|
| [yangchuansheng/clash-rules / Direct-Process.list](https://github.com/yangchuansheng/clash-rules/blob/35fe3ee6d4dfb65a558d2155a8033f320547c8dd/Direct-Process.list) | 2022-09-27 | Android 国内应用及 macOS 腾讯会议；文件较旧，只作历史交叉核对 |
| [Kyreth-VPN/public-configs / mihomo/rule-sets/packages/category-cn/rule.list](https://github.com/Kyreth-VPN/public-configs/blob/f816ca42b83521813f9b65b937c214e3bbd7730f/mihomo/rule-sets/packages/category-cn/rule.list) | 2026-07-18 | 按 Android 包名分类；含待确认的腾讯会议名称，不整份导入 |
| [Jacky-Bruse/Rules / Rules/directed.list](https://github.com/Jacky-Bruse/Rules/blob/a5e598094d56cf24199d0fab5f3b152791fcb838/Rules/directed.list) | 2026-09-29 | 京东、企业微信；微信规则已注释，不当作启用的证据 |
| [pichuanwenzi/Clash-bypasslist / applicationlist.txt](https://github.com/pichuanwenzi/Clash-bypasslist/blob/420a45f22d42db84fe517471ab47538703cc628b/applicationlist.txt) | 2026-04-16 | Windows/Android 大清单；部分条目只写厂商前缀，不能替代完整包名 |
| [bgpeer/rules / clash/meta.yaml](https://github.com/bgpeer/rules/blob/c5e870ed40ab848b89fdc1505d2ffe31d75a4b59/clash/meta.yaml) | 2026-10-07 | Threads/Instagram 或高德地图等完整 Android 包名 |
| [bgpeer/rules / clash/alibaba.yaml](https://github.com/bgpeer/rules/blob/c5e870ed40ab848b89fdc1505d2ffe31d75a4b59/clash/alibaba.yaml) | 2026-10-07 | Threads/Instagram 或高德地图等完整 Android 包名 |
| [Lbiebest/clash-config / rules/ProcessRules.list](https://github.com/Lbiebest/clash-config/blob/1fbf6a838b7911413c105adb5eda8fe962f54190/rules/ProcessRules.list) | 2025-12-26 | 微信 Windows 辅助进程、腾讯会议、向日葵等可执行文件名 |
| [liristy/ssrules / Rule/yaml/Application_CN.yaml](https://github.com/liristy/ssrules/blob/2d0f912f0f087efb74acc4cd5ced9687f0296126/Rule/yaml/Application_CN.yaml) | 2026-04-10 | Windows 应用及辅助进程；精确名称与正则规则混合 |
| [blackmatrix7/ios_rule_script / rule/Clash/Direct/Direct.list](https://github.com/blackmatrix7/ios_rule_script/blob/83f37120c155f67c8eef43221dabe15cc3c95fec/rule/Clash/Direct/Direct.list) | 2025-12-21 | 向日葵 macOS Desktop/Helper 名称 |
| [SukkaW/Surge / Source/non_ip/direct.conf](https://github.com/SukkaW/Surge/blob/1c454d540ff76a50e7828a7fe95583701905e306/Source/non_ip/direct.conf) | 2026-08-29 | 向日葵 Desktop/Helper 的另一份证据；Surge 语法需适配 |
| [IvanSolis1989/Smart-Config-Kit / rulesets/supplemental/clash/local-process-direct.list](https://github.com/IvanSolis1989/Smart-Config-Kit/blob/ada67a7579c729329707625c32311f57917e82bb/rulesets/supplemental/clash/local-process-direct.list) | 2026-07-14 | 本地补充规则，微信 AppEx 与向日葵 Windows Desktop/Service |
| [LM-Firefly/Rules / PROXY/Google.list](https://github.com/LM-Firefly/Rules/blob/d93766fbd7d4410917186ad73a24a79722d1ba67/PROXY/Google.list) | 2026-10-08 | Google 商店、服务、框架及 YouTube 包名 |
| [xOS/Config / RuleSet/Google.list](https://github.com/xOS/Config/blob/a9d57eb35ea7e98372a2c3a02b04e7bb0f580cdc/RuleSet/Google.list) | 2026-03-31 | Google 商店、服务、框架的交叉核对 |
| [KannaSakura/Rule-provider / PROCESS_CN_Android.yaml](https://github.com/KannaSakura/Rule-provider/blob/b5870ee35218a0a60c5046952dfb81dd7184a0e0/PROCESS_CN_Android.yaml) | 2024-04-06 | 隐藏在通用仓库中的 Android 进程表；包含向日葵，但文件较旧 |
| [LittleRey/clash-yaml / rules/CN-App.list](https://github.com/LittleRey/clash-yaml/blob/b9d754ddc5f5228abf33a7aded9b9dfb0d322f9e/rules/CN-App.list) | 2025-12-13 | 向日葵 Android 包名；微信等已注释 |
| [ghfree123/freedom / Twitter.list](https://github.com/ghfree123/freedom/blob/99edbac1f1bcac6d35a676e97bc242cd197c7221/Twitter.list) | 2026-02-05 | X/Twitter Android 包名；不自动补充 Lite/TV 等未指定版本 |

### Google／Cloudflare 204独立对照

手动运行“Google与Cloudflare 204对照”，指定最近完成的全量运行编号。读取该轮全部国内TCP通过节点，包括后续上行、网站或下载失败的节点；不更新订阅或生产筛选。Google使用`https://connectivitycheck.gstatic.com/generate_204`，Cloudflare使用`https://cp.cloudflare.com/generate_204`。每节点每目标三轮，交替先后顺序；同请求头、严格TLS、连接／读取超时2／3秒，三轮均返回无正文204才通过。16节点并行，两个目标在单节点内依次测，前后各三轮直连对照；直连异常时标记结果需复核。统计两者都过、仅Google过、仅Cloudflare过、两者都不过及逐节点延迟，报告只放Actions摘要和`compare-204`附件（7天）。这批节点已通过原Google204和国内TCP，不代表所有来源节点的无偏对照。

<!-- latest-detection:start -->
## 节点检测报告

**当前订阅：284 个节点。** 全量检测；报告更新 10-29 18:22:05（北京时间）。

本轮获取并去重 **7626** 个节点，可解析 **7623** 个。未入选节点不写入订阅。

另按用户要求加入 **1** 个“小草莓”免测节点（新增1个，重复定义共用已有节点）；仅放入独立手动分组和v2rayN订阅，不计入任何检测通过数，也不进入综合／下载／住宅优选组。

⭐ 综合优选 **155** · 🚄 中速下载 **279** · ⚡ 高速下载 **245** · 🏠 非机房 IP **15** · 🌏 台湾／新加坡 **4** · 🍓 小草莓（免测） **1**

分组会重叠，不能将数量相加；全局组手动选择、默认综合优选，其他优选组自动选择，免测组手动选择。

分组每5分钟自动检测HTTPS 200（claude.ai/cdn-cgi/trace）延迟，5秒超时；全局为select，默认综合优选；其他优选组为url-test，切换容差50ms，免测组无自动测速。客户端支持时可手动固定节点，不可用后可能自动切换。

### 测量时间

| 数据 | 完成时间（北京时间） |
|---|---|
| 全量检测批次完成（是否执行各项见阶段表） | 10-29 18:21:44 |
| 上行与负载后SSL | 10-29 18:16:53 |
| 持续并行稳定性 | 10-29 18:20:52 |

### 入选节点

| 节点 | P95 / P99 / 波动 ms | 下行 Mbps / 样本 | 上行 Mbps | 上传中204 | SSL | 成功轮数 / 成功率 |
|---|---:|---:|---:|---:|---|---|
| 美国01 | 242 / — / 15 | 4.2 / 5MB | 4.5 | 28/28 | 通过 | 17/17 / 100.0% |
| 美国02 | 254 / — / 17 | 181.7 / 100MB双轮 | 199.7 | 2/2 | 通过 | 20/20 / 100.0% |
| 美国03 | 268 / — / 32 | 178.8 / 100MB双轮 | 141.3 | 2/2 | 通过 | 20/20 / 100.0% |
| 美国04 | 280 / — / 13 | 113.4 / 100MB双轮 | 51.6 | 3/3 | 通过 | 20/20 / 100.0% |
| 美国05 | 281 / — / 23 | 180.0 / 100MB双轮 | 128.4 | 2/2 | 通过 | 19/19 / 100.0% |
| 美国06 | 287 / — / 12 | 131.9 / 100MB双轮 | 73.3 | 2/2 | 通过 | 20/20 / 100.0% |
| 美国07 | 288 / — / 16 | 10.6 / 5MB | 64.6 | 2/2 | 通过 | 20/20 / 100.0% |
| 美国08 | 292 / — / 31 | 89.1 / 100MB双轮 | 72.5 | 2/2 | 通过 | 20/20 / 100.0% |
| 美国09 | 294 / — / 22 | 4.1 / 5MB | 4.5 | 29/29 | 通过 | 17/17 / 100.0% |
| 美国10 | 300 / — / 28 | 10.8 / 5MB | 68.7 | 2/2 | 通过 | 20/20 / 100.0% |

仅展示排名靠前的最多10个节点，实际经测入选283个；上传速度未达标不等于普通节点淘汰。
近7天观察：跨日且覆盖昼夜的节点434个，证据待积累203个；晚间有观测452个。首次执行不能声称已验证多天稳定。

相比上一轮：观察节点-63，稳定性通过-110，结束仍未恢复+42，跨时段证据充分-9。


P95／P99取Google／YouTube各自成功请求统计中较慢的一站，波动为较大的四分位距；失败由成功率和连续失败次数单独计入排名。成功样本较少时P99接近最大值，仅作参考；每站样本数见JSON。下行优先双100MB较低速度，上行取两轮5MB较低速度；名称延迟仍用中位数。

### 每个环节的检测记录

| 检查阶段 | 实测 | 通过 | 未通过 | 未验证 | 未测／跳过 | 主要失败或跳过原因 |
|---|---:|---:|---:|---:|---:|---|
| 订阅来源获取 | 17 | 17 | 0 | 0 | 0 | 全部通过 |
| 去重后配置解析／字符检查 | 7626 | 7623 | 3 | 0 | 0 | 3：内核不支持或非法控制字符；不写入订阅 |
| 双204各三轮（均必过） | 7623 | 2027 | 5596 | 0 | 0 | 5184：Google204：连接、TLS 或读取失败；Cloudflare204：连接、TLS 或读取失败；158：Cloudflare204：连接、TLS 或读取失败 |
| Google204三轮 | 7623 | 2185 | 5438 | 0 | 0 | 5438：连接、TLS 或读取失败 |
| Cloudflare204三轮 | 7623 | 2125 | 5498 | 0 | 0 | 5498：连接、TLS 或读取失败 |
| 国内入口TCP | 1845 | 637 | 1208 | 0 | 5778 | 5596：204 未通过，未提交国内 TCP 检测；1208：该服务探测点 TCP 连接失败 |
| 网站TLS异常硬筛选 | 637 | 594 | 43 | 0 | 6986 | 6986：网站未测，未检查网站TLS；5：网站TLS异常：Amazon、Bing、ChatGPT、ChatGPTAPI、ChatGPTTrace、ClaudeTrace、Cursor、Discord、DisneyPlus、Facebook、Gemini、GitHub、Google、HuggingFace、Instagram、Netflix、Perplexity、Reddit、Spotify、StackOverflow、Steam、TikTok、Twitch、WhatsApp、Wikipedia、X、YouTube |
| 3MB上行预检 | 637 | 518 | 119 | 0 | 6986 | 6986：国内TCP未通过，未提交上行预检；119：上传未完整完成、响应异常、证书失败或超出预算 |
| 12站＋ChatGPT API＋必过trace | 637 | 411 | 226 | 0 | 6986 | 6986：国内TCP未通过，未进行网站检测；226：必过网页/API或trace未全部通过；各站原因见下表 |
| 应用SSL | 407 | 407 | 0 | 0 | 7216 | 7216：必过网站未通过，未提交应用TLS检查 |
| 1MB下载 | 407 | 400 | 7 | 0 | 7216 | 6986：未进入下载阶段；230：网站TLS异常或必过网页/API/trace未通过，跳过下载 |
| FAST API | 400 | 384 | 6 | 10 | 7223 | 7223：1MB未通过，未请求FAST API；10：FAST API未返回可信测速目标 |
| FAST CDN 1（1MB） | 384 | 374 | 10 | 0 | 7239 | 7239：FAST未返回该有效目标或前置1MB未通过；9：Netflix CDN连接、TLS或读取失败 |
| FAST CDN 2（1MB） | 384 | 374 | 10 | 0 | 7239 | 7239：FAST未返回该有效目标或前置1MB未通过；8：Netflix CDN连接、TLS或读取失败 |
| FAST CDN 3（1MB） | 384 | 371 | 13 | 0 | 7239 | 7239：FAST未返回该有效目标或前置1MB未通过；12：Netflix CDN连接、TLS或读取失败 |
| 5MB下载（中速组） | 400 | 394 | 6 | 0 | 7223 | 7223：1 MB快测未通过，未提交5 MB测试；6：未完整下载、响应文件不符或超出总时限 |
| Cloudflare 100MB | 400 | 325 | 75 | 0 | 7223 | 7223：1MB未通过，未进行100MB下载；75：未完整下载、响应文件不符或超出总时限 |
| DataPacket 100MB | 400 | 314 | 86 | 0 | 7223 | 7223：1MB未通过，未进行100MB下载；86：未完整下载、响应文件不符或超出总时限 |
| 双100MB下载（高速组） | 400 | 310 | 90 | 0 | 7223 | 7223：1 MB 快测未通过，未提交两轮100 MB测试；90：两轮100 MB下载未全部通过 |
| 两轮上行及上传中204 | 400 | 294 | 106 | 0 | 7223 | 7223：未进入合格候选池，未进行两轮上行检测；87：上传未完整完成、响应异常、证书失败或超出预算 |
| 上行观测完整性（非速度门槛） | 400 | 400 | 0 | 0 | 7223 | 7223：观测缺失或TLS异常；普通测速失败不等于淘汰 |
| 应用资源诊断（仅观察） | 407 | 407 | 0 | 0 | 7216 | 7216：前置网站或应用SSL未通过 |
| 5MB上行第1轮 | 400 | 387 | 13 | 0 | 7223 | 7223：未进入合格池，未执行该轮5MB上传；13：上传未完整完成、响应异常、证书失败或超出预算 |
| 5MB上行第2轮 | 400 | 323 | 77 | 0 | 7223 | 7223：未进入合格池，未执行该轮5MB上传；77：上传未完整完成、响应异常、证书失败或超出预算 |
| 上传后SSL | 400 | 330 | 70 | 0 | 7223 | 7223：未进行两轮上行，未进行上传后SSL检查；70：已检测但未满足通过条件，详见原始证据 |
| 持续并行稳定性 | 637 | 315 | 322 | 0 | 6986 | 6986：国内TCP未通过，未开始观察；317：持续观察成功率低于90% |
| 出口地区确认 | 637 | 619 | 0 | 18 | 6986 | 6986：出口IP／地区未确认或未进入网站阶段；18：出口IP／地区未确认或未进入网站阶段 |
| IP类型查询 | 619 | 619 | 0 | 0 | 7004 | 7004：出口未确认，不查询IP类型 |
| 住宅／纯净度查询 | 407 | 407 | 0 | 0 | 7216 | 7216：未入选候选池，不查询住宅／纯净度 |
| 最终配置校验 | 1 | 1 | 0 | 0 | 0 | 全部通过 |

未验证与真实失败分开；未测不计失败。TCP不适用于UDP，未提交的TCP探测列为跳过。FAST、5MB与100MB用于补测或分组，普通失败不等于综合池淘汰。稳定性独立并行，阶段计数不能相加。详细原因计数保存在最新检测JSON，逐次原始请求在本次Actions附件。

3MB及两轮5MB上行的“未通过”表示速度或负载表现未达原测速标准，不直接淘汰普通节点；最终需观测完整、TLS合格且持续稳定性达标。应用资源诊断的“通过”只表示检查已执行，实际资源结果另行汇总。


稳定性在国内TCP通过后独立并行检测，至少观察10分钟；3MB上行速度不阻挡观察。持续检测行不是最后一道串行统计。

各阶段仅检测满足前置条件的候选；同一节点可能在多项中失败，不能把失败数相加。逐网站及逐节点失败明细保存在JSON。

持续稳定性：**637**个候选，每节点**14～25**轮；通过**315**个，成功率低于90% **317**个，明确证书错误 **0**个。原因可能重叠。
### 各网站拦截与异常数量

统计范围 **7623** 个节点；仅实测节点进入各站分母。带★为逐站必过目标，其余目标仍参与整体覆盖率和证书校验。

| 网站 | 实测 | 通过 | CF人机验证 | 登录提示（通过） | 其他拦截／跳转 | 连接／TLS异常 | HTTP错误 | 慢／内容异常 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Amazon | 637 | 73 | 0 | 0 | 0 | 53 | 0 | 535 |
| Cursor | 637 | 485 | 0 | 0 | 1 | 124 | 0 | 43 |
| ★ Google | 637 | 536 | 0 | 0 | 49 | 69 | 0 | 6 |
| ★ Discord | 637 | 548 | 0 | 0 | 49 | 48 | 0 | 5 |
| ★ Gemini | 637 | 558 | 0 | 0 | 26 | 56 | 0 | 14 |
| Netflix | 637 | 568 | 0 | 0 | 4 | 59 | 0 | 31 |
| ★ ChatGPT | 637 | 577 | 30 | 0 | 8 | 55 | 0 | 18 |
| Steam | 637 | 585 | 0 | 0 | 0 | 50 | 0 | 13 |
| TikTok | 637 | 585 | 0 | 0 | 0 | 56 | 0 | 16 |
| DisneyPlus | 637 | 586 | 0 | 0 | 1 | 59 | 0 | 9 |
| ★ Telegram | 637 | 589 | 0 | 0 | 0 | 56 | 4 | 11 |
| ★ Reddit | 637 | 590 | 0 | 306 | 5 | 54 | 0 | 5 |
| ★ X | 637 | 590 | 0 | 0 | 1 | 54 | 0 | 7 |
| ★ ChatGPTAPI | 637 | 591 | 0 | 0 | 11 | 50 | 0 | 4 |
| HuggingFace | 637 | 591 | 0 | 0 | 5 | 53 | 0 | 5 |
| ★ YouTube | 637 | 592 | 0 | 0 | 0 | 56 | 0 | 5 |
| Bing | 637 | 594 | 0 | 0 | 2 | 54 | 0 | 5 |
| ★ GitHub | 637 | 594 | 0 | 0 | 0 | 49 | 0 | 7 |
| ★ Instagram | 637 | 594 | 0 | 0 | 2 | 48 | 0 | 6 |
| Twitch | 637 | 594 | 0 | 0 | 0 | 45 | 0 | 6 |
| WhatsApp | 637 | 594 | 0 | 0 | 0 | 55 | 0 | 8 |
| StackOverflow | 637 | 595 | 610 | 0 | 0 | 52 | 0 | 0 |
| Spotify | 637 | 596 | 0 | 0 | 4 | 48 | 0 | 6 |
| ★ Wikipedia | 637 | 596 | 0 | 0 | 6 | 41 | 0 | 7 |
| ★ Facebook | 637 | 599 | 0 | 0 | 4 | 43 | 0 | 2 |
| Perplexity | 637 | 603 | 109 | 0 | 0 | 49 | 0 | 1 |
| ChatGPTTrace | 637 | 612 | 0 | 0 | 0 | 32 | 0 | 0 |
| ★ ClaudeTrace | 637 | 612 | 0 | 0 | 0 | 33 | 0 | 0 |

数量按涉及节点计算，同一节点三轮中重复失败只计一个。通过包含已确认的Cloudflare人机验证及Reddit明确登录提示；没有这两类证据的普通403、429或跳转列入其他拦截／跳转，不能当作线路断开。异常原因列可能重叠，不相加。未测节点不算失败；完整数量见JSON的website_access_summary。

新版逐站通过允许一次普通连接失败且另外两次认可可达；已恢复的超时仍保留在异常计数。TLS、超时和恢复通过数量在JSON分别记录，任何TLS异常都不放行。

### 补充服务检测

FAST在1MB下载通过后检测；独立于网站覆盖率和下载分组，普通接口异常不淘汰节点，明确证书校验错误仍淘汰。

| 检测 | 实测 | 通过 | 限制 | CF验证 | 接口不可用／未知 | 连接／下载失败 | 证书错误 |
|---|---:|---:|---:|---:|---:|---:|---:|
| FAST测速API | 400 | 384 | 0 | 0 | 10 | 6 | 0 |
| Netflix CDN（按节点） | 384 | 359 | 0 | 0 | 0 | 25 | 0 |

CDN文件实测1152次：通过1119次，失败33次（其中证书错误0次）。

API通过表示取得预期响应；FAST请求3个不同CDN主机，依次各下载1MB、各限6秒；3个都通过才记为FAST通过，不足3个记为未知。均不代表登录、对话、视频播放或内容解锁成功。FAST API失败时CDN下载未测；JSON分别记录每个目标的状态、速度和成功样本速度范围／中位数。证书错误列可能与其他原因重叠。


YouTube资源诊断：检查407个节点，发现并请求808个资源，响应通过801次；未发现资源记未测。普通资源失败暂不作为新增淘汰条件，TLS异常仍淘汰；未验证真实视频播放或登录后ChatGPT对话。


### 稳定性分布

| 成功率区间 | 节点数 |
|---|---:|
| 100% | 292 |
| 99%～100% | 0 |
| 95%～99% | 6 |
| 90%～95% | 22 |
| <90% | 317 |

持续轮次为多个新连接、应用TLS和连接池请求的联合结果；请求数合计69696，连接池请求失败2364。
末尾尚未恢复250个节点；最长连续失败24轮。失败不混入成功响应P95，样本少于100不展示P99。

[本轮Actions及原始测量附件](https://github.com/hoooou/my_yml/actions/runs/40848099138)。原始附件保留7天。
<!-- latest-detection:end -->

## 2026-10-15 与 edgetunnel-template 同步

- **去掉 DNS fallback**：fake-ip 下走代理的域名由远端解析，本地解析结果只用于 IP 规则（GEOIP,CN）。被污染的答案是非 CN IP，照样走代理，所以 fallback 从未改变分流结果，只让未命中规则的域名等待经节点的 DoH。海外列表仍按 `nameserver-policy` 用 1.1.1.1 / 8.8.8.8 经 `🚀 全局选择` 解析，不变。
- **开启 sniffer**：浏览器安全 DNS、Android 私人 DNS、系统 DNS 缓存会让连接只带 IP，匹配不到任何域名规则而落到 MATCH。sniffer 从 TLS SNI / HTTP Host / QUIC 取回域名再按规则走；`override-destination: false`，实际连接的 IP 不变。
- **补充一个内网域名**：它在公网 DNS 上不存在，只能经内网 DNS 解析，与其他内网域名同样处理（DIRECT、不分配 fake-ip）。

