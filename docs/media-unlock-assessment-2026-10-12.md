# 解锁检测规格评估（2026-10-12）

状态：只读评估，未实施。输入为 `/Users/yc/Documents/dsh/media-unlock-detection-spec.md`；未发起真实节点请求，未修改生产代码、工作流或订阅。

## 结论

可以借鉴按服务检测、独立超时、有限并发、保存证据与时间戳的组织方式；不宜照搬原来的 `Yes/No/Failed` 判定来全量淘汰节点。此次核验的关键实现基本与文档相符，但“复现源码”不代表“已经证明解锁”。服务的网页/API可达、地区信息、账户/内容权限和性能应分别记录。

## 已核验的问题

1. **ChatGPT 的 Yes 有明确误判路径。**源码请求 cookie_requirements 后，只检测响应体是否包含 unsupported_country；公共 get_text 不检查 HTTP 状态。403、500、错误页等只要能读体且无该字串，也可能得到 Yes。这不能证明 ChatGPT 网页、登录或手机应用会话可用。[ChatGPT 检测源码](https://github.com/clash-verge-rev/clash-verge-rev/blob/27efaf3/crates/clash-verge-media-unlock/src/chatgpt.rs)、[get_text 源码](https://github.com/clash-verge-rev/clash-verge-rev/blob/27efaf3/crates/clash-verge-media-unlock/src/utils.rs)

2. **Claude trace 只提供地区线索。**原检测器只读 loc，再排除十个国家/地区；任何其他值都判 Yes。当前官方规定以支持列表为准，列表外并非默认支持，地区判断还会结合 IP 以外的信号。因此应标成“trace 可达／地区支持线索”，不能标成“已验证对话解锁”。[Claude 检测源码](https://github.com/clash-verge-rev/clash-verge-rev/blob/27efaf3/crates/clash-verge-media-unlock/src/claude.rs)、[官方支持地区](https://www.anthropic.com/supported-countries)、[官方位置说明](https://privacy.anthropic.com/en/articles/11186740-does-claude-use-my-location)

3. **Netflix 的地区字段取错了对象。**原检测器 fast.com targets 非空就提前返回 Yes，并将 targets[0].location.country 当作地区。核验当前 fast.com 第一方前端：targets 被归入 client.servers 并显示为 server-locations；用户地区单独使用 client.location。故 targets 地区是测速服务器地区，不能当节点出口/Netflix 内容地区。CDN 可达也不证明特定内容可播放。Netflix 官方说明 VPN 可能只显示全球授权内容，且某些观看场景不支持 VPN。[Netflix 检测源码](https://github.com/clash-verge-rev/clash-verge-rev/blob/27efaf3/crates/clash-verge-media-unlock/src/netflix.rs)、[fast.com 当前前端源码](https://fast.com/app-0bffe1.js)、[Netflix 官方 VPN 说明](https://help.netflix.com/en/node/114701/)

4. **Disney+ 回退会乐观判定。**GraphQL 失败时，原实现仅从首页抽取 region 字段就返回 Yes；countryCode=JP 也在检查 inSupportedLocation 前返回 Yes。这些分支无法单独证明设备授权成功或内容可播放。此外任意递归找第一个同名键可能取到不同语义的数据；实现应验证字段所在对象和类型，不能以“更抗改版”替代语义验证。[Disney+ 检测源码](https://github.com/clash-verge-rev/clash-verge-rev/blob/27efaf3/crates/clash-verge-media-unlock/src/disney_plus.rs)

5. **不能关闭目标网站 TLS 验证。**原客户端确实关闭证书和主机名验证；文档据此推荐关闭，但未给出“严格验证必然造成站点拒绝”的证据。证书校验主要发生在客户端，关闭校验不能可靠解决服务端浏览器指纹限制。对本项目尤其会遮蔽手机已报告的 SSL 异常，应保留验证并将证书错误单独记录。[原客户端](https://github.com/clash-verge-rev/clash-verge-rev/blob/27efaf3/src-tauri/src/cmd/media_unlock_checker/mod.rs)

6. **403 不能统称地区不支持或封 IP。**Cloudflare 官方列出的原因包括权限、WAF、挑战、浏览器检查及 SNI 不匹配。应解析明确的服务限制证据，区分限制、挑战、限流、检测错误、网络/TLS 失败；已有“明确 Cloudflare 挑战不算一般网页失败”的用户要求应保留，但挑战不等于登录/内容解锁。[Cloudflare 403 说明](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-403/)

## 国产网站是否参与筛选

建议不以经代理访问普通国产网站的成败淘汰海外节点。这是针对本项目直连规则与用户目标的工程判断：国产应用走 DIRECT 时，云端经节点访问国内站点测到的是另一条路线，不能表示手机直连体验，也不能表示中国移动到节点入口的连通性。保留国内入口 TCP 探测；国产网页若需要，做直连规则/DNS诊断或单独“大陆内容回国访问”能力标签。B站版权接口适合检验某部作品的地区播放权限，不适合作为所有海外节点通用质量门槛。

当前代码已将国内网页排除在海外必过条件、海外覆盖计数与排名之外，但仍逐节点请求13个国内网页。读取04:40发布报告中10个已入选节点的历史网页记录：B站10个全部需复核，微博7个失败，京东9个需复核、1个失败。这些不是本次新测数据，也不能据此断定手机直连失败。建议后续取消每日逐节点国内网页请求，只在专项诊断时启用；国内域名直连/DNS规则和国内入口TCP仍有不同用途，应保留。

## 建议后续接口与发布策略

- 每项保存 `service_id/status/reason/evidence/http_status/latency/region_source/checked_at/detector_version`，明确区分通过、限制、挑战、超时、检测器失效与未验证；解析结构变化记为检测错误，不应直接证明节点不支持。
- 第一阶段只对通过现有入口/稳定性门槛的节点补充能力报告，不新增全服务全过硬门槛，不改节点名称格式。Netflix/Disney+/B站等作为可选能力，不挤掉适合日常网页的节点。
- 批量全失败需先核对直连控制与响应样本，暂停该检测器淘汰作用。服务检测结果不替代低延迟、吞吐量与间隔复测。
- 后续可按用户真正需要的服务建立候选分组；当前不实施分组增加。无账号公开探测不能证明付费内容或已登录 ChatGPT 会话成功。

## 上行速率初步方案（建议，未实测）

Cloudflare 第一方测速库默认将上传请求发往 `https://speed.cloudflare.com/__up`；当前引擎追加 `?bytes=NUM` 并 POST 等长 body，检查响应成功，官方浏览器算法用 TTFB 计算上传速率。可参考 `__up?bytes=5000000`，但仍需验证当前端点响应契约。[Cloudflare speedtest README](https://github.com/cloudflare/speedtest)、[官方 BandwidthEngine](https://github.com/cloudflare/speedtest/blob/main/src/engines/BandwidthEngine/BandwidthEngine.ts)

旧 Worker 模板 README 说接收完整 body 后响应，但其上传源码直接返回 `Response('ok')`，未读取 body；不能以此证明官方 `__up` 已确认服务端收到逐字节完整数据。实现前需在 Actions 做小批验证，核查早返回、响应状态和取消行为。[旧 Worker 文档](https://github.com/cloudflare/worker-speedtest-template#upload)、[旧上传源码](https://github.com/cloudflare/worker-speedtest-template/blob/master/src/up.js)

建议先仅对通过现有稳定性门槛的优选候选做影子报告：1MB 上传预检，接着 5MB 上传两轮，各轮限时10秒，间隔15–30秒，每节点初拟上行流量11MB。使用随机/不可压缩合成body、严格HTTPS证书验证、禁止重定向；应要求完整body发完且收到预期服务端响应，并排除早返回影响。单独200、客户端发送缓冲进度或查询参数不能当作服务端已经接收的字节量。拟按完整提交字节数乘8除以请求总耗时计算Mbps，两轮取较低值；此公式是保守端到端小文件采样，与官方浏览器TTFB算法数值不等同，不能当成线路峰值带宽。过短采样可在后续试验中增大文件确认，不先引入100MB上传。

每个分片同时上传 1–2 个节点，全局最多 4 个，不与下载同时执行；上传前、中、后测 204 延迟以观察负载下响应变化。首轮只报告，不设硬淘汰阈值，先观察接口限流、错误率与重复测试偏差，避免测速器问题误杀。以上请求规模和阈值是工程建议，未进行实测。GitHub Actions 到节点再到 Cloudflare 的上传路径只能作为参考；国内移动 TCP 入口探测不能证明用户移动网络的上行速率。

## 核验范围限制

核验了 revision 27efaf3 的 ChatGPT、Claude、Netflix、Disney+、公共工具及客户端；其余八项未逐项复核。当前 fast.com 脚本文件名会随发布变化，本笔记记录核验当天版本。未验证静态 title IDs、Disney+ 常量或其他站点 DOM 标记今天仍适用。此次未进行任何真实出口解锁测试。
