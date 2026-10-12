# 服务接口接入与云端验证

## 最终流程

- 网站阶段：原12个必过页面加ChatGPT API，每个目标三轮；Claude trace单轮。ChatGPT API正常响应须为正确HTTPS地址、HTTP200、JSON且`cookie_consent_required`为布尔值，记录响应头及正文耗时。沿用明确CF验证的可达例外，普通错误页、跳转和无预期字段不判正常通过。未通过跳过应用TLS和下载。
- TikTok保持原首页检测与筛选逻辑，不增加trace目标或必过条件。
- 现有Cloudflare 1MB下载通过后：FAST API通过`urlCount=3`获取最多三个可信Netflix CDN目标，按主机名去重，依次拼接1MB范围，每个各限6秒完整下载。三个都通过才记为FAST通过；返回不足三个记为未知，不能重复凑数，也不保证三个主机属于不同物理服务器或地区。每个目标保留独立状态、速度、耗时，汇总成功目标的速度中位数及范围。FAST API及CDN结果单独统计，普通失败不新增淘汰条件、不替代原下载分组标准；明确证书校验错误仍淘汰。

## 地址验证及修正

[第一轮](https://github.com/hoooou/my_yml/actions/runs/38211803387)和[响应结构复查](https://github.com/hoooou/my_yml/actions/runs/38212157289)均在GitHub Actions运行，没有本地节点实测。

| 目标 | 发现 | 处理 |
|---|---|---|
| ChatGPT cookie接口 | 三个204通过样本和前后直连对照均返回有效JSON | 放入网站阶段，三轮必过；不将cookie接口可达宣称为对话成功 |
| FAST API | HTTP200且有targets，但当前返回`/speedtest`基址；初版只接受已拼接的范围路径，误记未知 | 对照官方客户端，把合法基址拼接为`/speedtest/range/0-999999`，保留签名查询，仅接受HTTPS Netflix CDN；修正后重测 |
| TikTok trace | 三个可用样本及前后直连均302到`https://www.tiktok.com/404`；跟随得到HTTP200的HTML错误页，没有trace | 用户选择取消该目标，保持原TikTok逻辑；不将接口不支持当作节点失效 |

FAST拼接依据：[官方客户端](https://fast.com/app-0bffe1.js)在获取targets后将`speedtest`替换为`speedtest/range/`，下载时附加范围。仅API返回不构成带宽或内容解锁证据。响应中的CDN地区不是代理出口地区。

## 单目标版本的小样本结果

[最终验证](https://github.com/hoooou/my_yml/actions/runs/38213158100)使用提交`3fcc879`，离线205项测试及工作流检查通过。该只读任务包含四个已发布样本和前后直连对照，不更新订阅。

| 范围 | 204三轮 | 生产方式ChatGPT API三轮 | FAST目标获取 | Netflix CDN完整1MB |
|---|---:|---:|---:|---:|
| 三个当时仍可连通的样本 | 3/3节点 | 3/3节点，9/9请求 | 3/3 | 3/3 |
| 另一个当时已超时的样本 | 未通过 | 未通过 | 未通过 | 未测 |
| 前后直连对照 | 未提交 | 单次接口均通过 | 均通过 | 均通过 |

三个样本的CDN下载耗时为1850.3、1754.4、2456.5ms，均收到HTTP200、`application/octet-stream`、声明及实收1,000,000字节；包含建连的速度分别4.32、4.56、3.26Mbps。小文件结果不是持续峰值带宽，且来自GitHub云端。结果验证了检测路径，不证明整个订阅已按新门槛完成全量重测；新条件在下一轮全量采用。

报告仅保留目标域名/路径、状态、耗时、长度和安全的解析字段，不保留Cookie、签名查询或原始响应正文。所有HTTPS请求保持证书校验；未模拟应用证书固定、登录后会话或实际视频播放。
