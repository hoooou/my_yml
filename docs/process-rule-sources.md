# 进程规则代码搜索核对记录

核对日期：2026-10-10。使用 GitHub 已认证代码搜索 API，按文件内容检索，没有以仓库名称作为筛选条件。共执行 10 组搜索，读取 15 个仓库中的 16 份规则文件，并查询这些文件自身的最近提交时间。搜索默认分支索引，抽取每组前 10–20 项进行针对性核对，不代表穷尽所有仓库；重复生成、镜像或相互借用的规则不算独立实测。

查询使用 `"PROCESS-NAME"` 加以下关键字：`com.tencent.mm`、`com.tencent.wework`、`SunloginClient`、`com.instagram.barcelona`、`com.autonavi.minimap`、`wemeetapp`、`com.android.vending`、`WeChatAppEx`、`com.twitter.android`、`com.oray.sunlogin`。例如：

```text
"PROCESS-NAME" "com.instagram.barcelona"
"PROCESS-NAME" "SunloginClient"
```

## 实际文件来源

链接固定到搜索命中的提交版本；日期为 2026-10-10 查询时该文件在默认分支上的最近提交日期（UTC），不是整个仓库的更新时间，也不等于作者最近做过实机验证。列出的文件均可读取；仓库当时未归档。仅选取需要的名称，不整份导入其他人的策略、节点或脚本。

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

## 本次采用的补充

- **向日葵 macOS**：补上 `SunloginClient_Desktop` 和 `SunloginClient_Helper`，同时出现在 blackmatrix7 与 SukkaW 的实际规则里。此前已有的 `SunloginClient` 等别名保留。
- **向日葵 Windows**：从 Smart-Config-Kit 的补充规则增加 `SunloginClient_Desktop.exe`、`SunloginClient_Service.exe`。
- **微信 Windows**：补上 `WeChatAppEx.exe`，在 Smart-Config-Kit、Lbiebest 和 liristy 的实际规则中都有对应条目；继续直连。
- **Google Play 相关服务**：补上 `com.google.android.gsf`，与现有 `com.android.vending`、`com.google.android.gms` 一起代理。LM-Firefly 和 xOS 均有此名称；框架本身的其他 Google 服务流量也会走代理，不单限于商店页面。

这是有代码出处的兼容名称补充。测试中以新增的微信 AppEx 和向日葵 macOS Desktop/Helper 名称运行独立 HTTP 客户端，确认 Mihomo 能识别真实执行进程并命中预期规则。Windows 名称完成来源核对，未在 Windows 实机验证；没有安装向日葵或在手机上运行上述应用，不能据此宣称所有版本都已实机验证。Android 仍需 FlClash 的连接记录确认识别到的包名。

## 不采用的写法及核对结果

1. Kyreth 的分类表包含 `com.tencent.wemeet`，本次不采用。腾讯官方应用的[小米应用商店页面](https://app.mi.com/details?id=com.tencent.wemeet.app)明确列出 `com.tencent.wemeet.app`；yangchuansheng 的规则也使用后者，当前配置保持这个完整包名。
2. 部分 Android 参考说明把 `com.autonavi.minimap` 标成“旧包名”；[官方 Google Play 高德地图页面](https://play.google.com/store/apps/details?id=com.autonavi.minimap)仍使用它。当前配置保留，不根据单个清单替换成未经确认的其他包名。
3. pichuanwenzi 的大清单里存在 `PROCESS-NAME,com.tencent.tmgp`、`PROCESS-NAME,com.netease` 等厂商前缀样式；Mihomo 的普通 PROCESS-NAME 是名称匹配，这些文字不能自动覆盖厂商的所有完整 Android 包名。也不导入其浏览器及其他未指定应用直连选择。
4. Surge 原文件还包含 `USER-AGENT` 和 `PROCESS-NAME,qbittorrent*` 等写法；Mihomo 的规则类型及通配符语义需逐项适配，不能因为同为 `.list` 就直接整份订阅。我们只抽取本次需要的精确进程名称。
5. 被注释的规则只代表历史或候选写法，不当作当前已启用证据；多个配置采用同一名称也只能增强线索，不能取代官方包名和本地真实进程信息。

Android 包名已有交叉证据：微信、微博、美团、拼多多、京东、高德地图、企业微信见国内进程表；向日葵见 KannaSakura/LittleRey 并与[官方开发者的小米应用商店页面](https://app.mi.com/details?id=com.oray.sunlogin)一致；腾讯会议见上方官方页面；X 见 ghfree123；Google Play/YouTube 见 LM-Firefly；Threads 见 bgpeer。手机是否能识别应用还取决于 VPN 流量是否进入核心和系统支持，包名正确不等于当前客户端已成功获取进程。

## 配置与验证

应用目录为 `scripts/app_catalog.py`。公司域名/局域网优先，保留广告拦截，然后匹配个人进程例外及指定应用，最后进行域名兜底。不固定浏览器、Python、Node、Git 或通用 Helper 的整个进程；不增加策略组，也不改变测速流程。

内置规则由每日发布及手动 repair 统一生成。本次仍采用审核后的快照，不让外部清单更新自动改变用户指定的直连/代理选择。已有域名/IP 维护规则集继续按原方式刷新。
