# Clash 节点优选

`聚合配置.yaml` 是订阅源和分流规则的输入；`优选配置.yaml` 是自动筛选后可直接导入的完整配置，适用于 Clash Meta / Mihomo 客户端。

## 使用

在客户端中添加远程配置：

```
https://raw.githubusercontent.com/hoooou/my_yml/main/%E4%BC%98%E9%80%89%E9%85%8D%E7%BD%AE.yaml
```

将客户端的远程配置刷新间隔设为 24 小时。GitHub 更新文件后，客户端仍需要刷新才能加载新节点。

默认选择“⚡ 速度优先”，依次使用本次测速排名中的可用节点；“♻️ 低延迟”按客户端运行时的延迟自动选择；“🎯 手动选择”和地区分组用于手动指定节点。

## 每日更新

GitHub Actions 的“每日节点优选”每天北京时间 **08:00 开始**，也可以在 Actions 页面点击 **Run workflow** 手动运行。GitHub 定时触发可能延迟，08:00 是计划开始时间，不是配置更新完成时间。

1. 拉取 `聚合配置.yaml` 中的 11 个订阅源。下载失败的源记录在报告中，其余继续。
2. 按完整连接配置去重并通过 Mihomo 解析校验，保留不同认证参数的节点。
3. 对全部节点访问 Google 204 地址，剔除失败或延迟超过 1000 ms 的节点。
4. 从延迟最低的最多 150 个候选中，用 [faceair/clash-speedtest v1.8.8](https://github.com/faceair/clash-speedtest/tree/v1.8.8) 下载 8 MiB 文件，要求速度至少 0.5 MiB/s，6 次 HTTP HEAD 请求失败率不超过 20%。
5. 对文件测速合格的较快节点串行复测，要求完整下载 4 MiB 文件；通过节点访问 Cloudflare trace，按**实际出口 IP 的国家/地区**命名。取两次下载速度中较低的值排名，延迟作为次排序，保留最多 30 个节点。
6. 生成完整配置，保留原始分流规则，使用 Mihomo 校验后提交 `优选配置.yaml`、`测速报告.json` 和 `测速报告.md`。

节点名示例：`日本 JP | abc123 | 3.20MiB/s | 180ms`。MiB/s 为下载单位，1 MiB/s 约为 8.39 Mbps。地区与延迟/速度均来自检测结果，不采用订阅中的广告名称。不同测试网站可能使用不同出口，地区代表本次 Cloudflare 请求出口。

运行地点是 GitHub 云端，结果可能与家庭网络不同。“低延迟”组会在你本机重新测延迟。初筛延迟为 Google 204 请求耗时，文件测速延迟为 6 次 HEAD 请求平均值；报告分别列出两者。HEAD 失败率不是 ICMP 丢包率。测试不验证 UDP 或 ChatGPT 等服务的解锁。

合格节点不足 30 个时按实际数量输出；全部失败时任务失败并保留上次配置。文件测速只覆盖低延迟候选，不保证得到所有订阅的全局最快 30 个节点。规则保持原有顺序；新配置移除了未引用的规则源、订阅锚点和原来仅对未筛选订阅生效的分组。

GitHub 对长时间没有活动的公共仓库可能停止定时任务，可在 Actions 页面重新启用。本任务成功发布会提交更新记录。查看 [GitHub 定时任务说明](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)。

## 修改筛选条件

编辑 `.github/workflows/select-nodes.yml` 中的 `--limit`、`--candidate-limit` 和 `--max-latency-ms`。最低下载速度、文件大小和复测条件在 `scripts/select_nodes.py` 中定义。工具版本和 SHA-256 固定在 `scripts/install_tools.py`。

本机复现时安装 `scripts/requirements.txt`，准备对应系统的 Mihomo 和 clash-speedtest 可执行文件，运行：

```sh
python scripts/select_nodes.py --mihomo /path/to/mihomo --speedtest /path/to/clash-speedtest --limit 30 --test-origin local
```

测速使用独立内核、临时本机端口，不打开 TUN，也不修改系统代理。源订阅的 YAML 格式是当前支持的输入格式。
