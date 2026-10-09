# Clash 节点优选

`聚合配置.yaml` 是原订阅源和分流规则的输入，`节点来源.yaml` 是新增的公开免费来源清单；`优选配置.yaml` 是自动筛选后可直接导入的完整配置，适用于 Clash Meta / Mihomo 客户端。

## 使用

在客户端中添加远程配置：

```
https://raw.githubusercontent.com/hoooou/my_yml/main/%E4%BC%98%E9%80%89%E9%85%8D%E7%BD%AE.yaml
```

将客户端的远程配置刷新间隔设为 24 小时。GitHub 更新文件后，客户端仍需要刷新才能加载新节点。

默认选择“⚡ 速度优先”，依次使用本次测速排名中的可用节点；“♻️ 低延迟”按客户端运行时的延迟自动选择；“🎯 手动选择”和地区分组用于手动指定节点。每个地区分组只含该地区本次排名前 30 个；“🏠 非机房 IP”按下载速度排序，在最多 30 个不同出口 IP 之间自动切换。

## 每日更新

GitHub Actions 的“每日节点优选”每天北京时间 **08:00 开始**，也可以在 Actions 页面点击 **Run workflow** 手动运行。GitHub 定时触发可能延迟，08:00 是计划开始时间，不是配置更新完成时间。

1. 每次运行重新拉取 `聚合配置.yaml` 中的 11 个订阅源和 `节点来源.yaml` 中的 6 个新增来源，共 17 个地址。使用分支的最新配置地址，不缓存昨天的节点；下载失败的源记录在报告中，其余继续。
2. 仅提取各配置的 `proxies`。忽略节点名称，统一服务器地址大小写、端口数字和 UUID 大小写，再按完整连接配置去重并通过 Mihomo 解析校验；不同密码、UUID、TLS 或传输参数仍保留。
3. 对全部节点访问 Google 204 地址，剔除失败或延迟超过 1000 ms 的节点。
4. 延迟合格后，通过每个节点访问 Cloudflare trace 获取实际出口 IP 和国家/地区，先分类再测速。地区未知的节点跳过。对独立出口 IP 使用 [ip-api.com](https://ip-api.com/docs/api:json) 批量查询 IP 类型，记录 `hosting`、ISP、ASN、移动网络和代理标签。免费批量接口最多 100 IP/请求、15 请求/分钟；程序按窗口限流，失败或缺少类型字段的 IP 记为未知。
5. 对每个地区的**全部分类成功节点**，用 [faceair/clash-speedtest v1.8.8](https://github.com/faceair/clash-speedtest/tree/v1.8.8) 下载 `http://lax.download.datapacket.com/10mb.bin`，实际大小 10,000,000 字节（10 MB），要求速度至少 0.5 MiB/s、6 次 HTTP HEAD 请求失败率不超过 20%、文件请求平均延迟不超过 1000 ms。没有全局或各地区 150 个候选上限。
6. 工具测速通过后，再完整下载**同一个 10 MB 文件**；检查字节数和 SHA-256 与本轮直连对照一致，剔除未完整下载、内容被替换或低于最低速度的节点。分类后出口 IP 或地区改变的节点也剔除。两次下载速度取较低值排名，延迟作为次排序。
7. 每个国家/地区独立保留最多 30 个节点。另外从全量测速合格节点中选择 `hosting=false` 的非机房节点，按出口 IP 去重，再取速度最高、延迟次优的最多 30 个。两个榜单取并集，配置中的共同节点只保存一份。地区分组只列本地区榜单，非机房分组只列非机房榜单。
8. 生成完整配置，保留原始分流规则，使用 Mihomo 校验后提交 `优选配置.yaml`、`测速报告.json` 和 `测速报告.md`。

节点名示例：`日本 JP | abc123 | 3.20MiB/s | 180ms`。MiB/s 为下载单位，1 MiB/s 约为 8.39 Mbps。地区与延迟/速度均来自检测结果，不采用订阅中的广告名称。不同测试网站可能使用不同出口，地区代表本次 Cloudflare 请求出口。

运行地点是 GitHub 云端，结果可能与家庭网络不同。“低延迟”组会在你本机重新测延迟。初筛延迟为 Google 204 请求耗时，文件测速延迟为 6 次 HEAD 请求平均值；报告分别列出两者。HEAD 失败率不是 ICMP 丢包率。测试不验证 UDP 或 ChatGPT 等服务的解锁。

每个地区和非机房分组各自不足 30 个时按实际数量输出；合格节点为零的地区不生成分组。非机房分组为零时只提供 `REJECT`，不会把机房或未知 IP 补入。全部测速失败时任务失败并保留上次配置。地区或 IP 类型数据库分类可能有误；“非机房”不保证是住宅网络、原生 IP 或可以解锁某个服务。规则保持原有顺序；新配置移除了未引用的规则源、订阅锚点和原来仅对未筛选订阅生效的分组。

GitHub 对长时间没有活动的公共仓库可能停止定时任务，可在 Actions 页面重新启用。本任务成功发布会提交更新记录。查看 [GitHub 定时任务说明](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)。

## 新增公开来源

以下 6 个配置在 2026-10-09 接入检查时均能下载、包含非空 YAML 节点列表，且对应配置文件最近 24 小时内有提交更新。来源的自动更新时间由各项目控制，本仓库仍在每天北京时间 08:00 拉取和重新测速。

| 项目 | 最新分支配置文件 |
|---|---|
| [BestClash](https://github.com/PuddinCat/BestClash) | `main/proxies.yaml` |
| [Au1rxx/free-vpn-subscriptions](https://github.com/Au1rxx/free-vpn-subscriptions) | `main/output/clash.yaml` |
| [anaer/Sub](https://github.com/anaer/Sub) | `main/clash.yaml` |
| [AutoMergePublicNodes](https://github.com/chengaopan/AutoMergePublicNodes) | `master/list.yml` |
| [V2RayAggregator](https://github.com/mahdibland/V2RayAggregator) | `master/Eternity.yml` |
| [zhuhaiuk/free-nodes](https://github.com/zhuhaiuk/free-nodes) | `main/clash_config.yaml` |

原订阅的 a1 已从固定历史提交地址改为 Gist 最新版本地址；a7 改为 GitHub 原始配置地址。新来源的节点仍需通过本仓库的完整测速，来源自带的速度或地区标签不作为入选依据。

每次报告列出各来源的下载数量、新增唯一节点、重复数、跳过数、下载状态和内容指纹；每个入选节点记录全部匹配来源。新增唯一数按清单顺序计算，不是来源有效率或速度排名。

编辑 `节点来源.yaml` 的 `sources` 列表可添加来源，`id` 必须唯一，`url` 应是固定的 HTTPS YAML 地址；设 `enabled: false` 可停用。只读取来源节点，不导入外部配置的规则、分组、脚本或本地设置。长期失效、停止更新或只能提供日期文件的候选本次没有接入。

## 修改筛选条件

编辑 `.github/workflows/select-nodes.yml` 准备步骤中的 `--per-region-limit`（每地区上限）、`--non-datacenter-limit`（非机房独立出口上限）和 `--max-latency-ms`。最低下载速度、文件大小和复测条件在 `scripts/select_nodes.py` 中定义。工具版本和 SHA-256 固定在 `scripts/install_tools.py`。

本机复现时安装 `scripts/requirements.txt`，准备对应系统的 Mihomo 和 clash-speedtest 可执行文件，运行：

```sh
python scripts/select_nodes.py --mihomo /path/to/mihomo --speedtest /path/to/clash-speedtest --per-region-limit 30 --non-datacenter-limit 30 --test-origin local
```

测速使用独立内核、临时本机端口，不打开 TUN，也不修改系统代理。源订阅的 YAML 格式是当前支持的输入格式。

流程分成地区/IP 分类、各地区文件测速、筛选与发布三个步骤；正常会比只测 150 个候选耗时更长。工作流上限 180 分钟，每次同时测试两个节点、每节点一个下载流。IP 类型查询无需账号或密钥，免费接口适用于个人非商业用途；未知类型不进入非机房榜单。
