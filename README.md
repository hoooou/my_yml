# Clash 节点优选

`聚合配置.yaml` 是原订阅源和分流规则的输入，`节点来源.yaml` 是新增的公开免费来源清单；`优选配置.yaml` 是自动筛选后可直接导入的完整配置，适用于 Clash Meta / Mihomo 客户端。

## 使用

在客户端中添加远程配置：

```
https://raw.githubusercontent.com/hoooou/my_yml/main/%E4%BC%98%E9%80%89%E9%85%8D%E7%BD%AE.yaml
```

将客户端的远程配置刷新间隔设为 24 小时。GitHub 更新文件后，客户端仍需要刷新才能加载新节点。

默认进入“⚡ 快速下载通过”组；无完整采样通过时使用其他可用分类。手机继续刷新原订阅即可，不需要更换链接。可切换“🔎 204未通过”“📶 TCP通”“⛔ TCP不通”“🔎 TCP未验证”做本地对照。全部内核可解析且手机兼容的节点保留；地区及非机房优选组最多各 30 个。

## 每日更新

GitHub Actions 的“每日节点连通性分类”每天北京时间 **08:00 开始**，也支持手动触发。四个免费标准 Actions 分片并行，每片最多同时处理 16 个节点；同一节点按下面的顺序过关，不同节点可以同时处于不同阶段，不等待全量上一阶段结束。

1. 获取原配置 11 个来源和新增 6 个公开来源的最新节点，按连接配置去重；不同密码、UUID、协议或传输参数保留。内核不支持或包含非法控制字符的节点在报告记录，不写入手机订阅。
2. **先批量检查 HTTPS 204，独立请求三轮**：`https://connectivitycheck.gstatic.com/generate_204`。三次均返回无正文的 204 才继续；记录每轮延迟、中位数和最大值。不通过的节点保留在“204未通过”，TCP 归为未验证，不伪造国内入口失败。
3. **再进行国内 TCPing**：仅对 204 通过且支持 TCP 的主机/端口调用小小 API，一入口一次。共享入口只提交一次，不同凭据的节点独立检查 204 和后续访问。四片合计约不超过 5 次请求/秒。明确连接失败记为“不通”，接口限流、异常、超时或目标不匹配记为“未验证”。UDP 的 TCP 阶段不适用，保留供手机对照。
4. **再检查海外网站和 trace，各一次**：Google、YouTube、ChatGPT 网页及 ChatGPT/Claude trace 五个地址并行请求。网页仅读取前 16 KB，403/验证码/风控需人工复核。trace 必须匹配预期域名、公网出口、地区和 HTTPS 标识；通过只说明域名 HTTPS 连通，不说明可以登录、对话或播放视频。不同项目独立分组；“三站通过”是三张网页单轮通过，“三项连通”是 204 三轮及两个 trace 单轮通过。
5. **最后 Cloudflare 快速下载一次**：TCP 通且至少一个海外网页或 trace 通过后，通过同一个节点访问 [官方 1 MB 下载地址](https://speed.cloudflare.com/__down?bytes=1000000)。请求禁止重定向和压缩，响应状态、类型、声明长度及完整字节数都匹配才通过。读取超时 1 秒，采样预算 6 秒；达到预算就停止读取，底层建连/读取还可能等待其自身超时。记录完整 1 MB 的速度及耗时，包含 TLS 与首字节等待，属于快速采样速度，不是峰值带宽。
6. 排名先选择完整下载通过，再比较网页通过项数、三项连通通过数、204 中位延迟、下载速度及 TCP 延迟。地区组及非机房组只从下载通过的节点选取；地区取实际 trace 出口地区，各最多 30 个；非机房要求明确 `hosting=false`、不同 trace 未发现出口不一致，并按独立出口 IP 最多取 30 个。未确认 IP 类型不进入非机房组。
7. 四片结果全部合并，检查批次、完整覆盖、各阶段顺序和轮数、下载完整性。缺片或漏测拒绝发布。Mihomo 最终配置校验通过后，更新原订阅和 `连通性报告.json/md`。分片临时文件保留 1 天。

Cloudflare 官方测速引擎使用 `https://speed.cloudflare.com/__down`，`bytes` 参数指定字节数，见[官方项目](https://github.com/cloudflare/speedtest)。本流程使用 1,000,000 字节（1 MB），无需安装或调用 clash-speedtest。

探测服务：

| 服务 | 当前用途 |
|---|---|
| [小小 API](https://xxapi.cn/doc/tcping) | 国内 TCPing 自动分类；运营商未公开，不能称为移动线路实测 |
| [ITDOG](https://www.itdog.cn/batch_tcping/) | 网页人工对照；未接入可用的全量自动接口 |
| [TCPING.CN](https://www.tcping.cn/tcping) | 网页人工对照；自动接口要求人机验证时跳过 |

每轮记录另外两家服务状态，不宣称三家都完成自动探测，不绕过人机验证。TCP 结果仅代表所测探测点，海外访问和下载速度来自 GitHub 云端，仍需手机对照中国移动的实际体验。

发布前检查所有解码字段，剔除非法控制字符，避免 FlClash 重新生成配置后报 `control characters are not allowed`。正常中文和图标保留。手动触发选择 `repair` 仅修复已有配置，不进行网络检测，保留原测量时间、原轮数和原下载设置；每日任务及默认 `full` 执行最新分阶段流程。

`测速报告.*`、`移动小测报告.*` 是历史结果，以 `连通性报告.*` 为准。原分流规则及手机订阅地址保留；所有来源失效或配置不能校验时保留旧订阅。

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

入口和分阶段检测位于 `scripts/availability.py`，网页及 trace 的响应校验位于 `scripts/mobile_pilot.py`。工作流只安装 Mihomo，使用独立节点监听端口，不打开 TUN、不修改系统代理。旧下载测速脚本仅用于历史复现，当前工作流使用直接 HTTP 的 1 MB 快速采样。

地区最多 30 个及非机房独立出口最多 30 个只限制优选分组，不影响全部样本与对照分类。定时触发可能延迟；GitHub 长时间无活动可能暂停定时任务。
