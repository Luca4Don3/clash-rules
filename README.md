# Clash / Shadowrocket 分流规则

默认未命中流量直连；广告与恶意域名拦截；国内服务直连；AI、券商和交易所等敏感服务使用独立的手动节点组。用户的策略选择由客户端持久化，不会宣称或依赖“直连失败自动重试代理”。

## Clash Verge Rev（推荐）

在“设置 → 全局扩展 → 新建 JavaScript”中使用：

```text
https://raw.githubusercontent.com/Luca4Don3/clash-rules/master/clash/clash-verge-script.js
```

脚本保留机场节点、provider、原策略组和 DNS，并幂等添加：

- `日常代理`：自动测速所有真实节点，过滤流量、到期、官网、套餐等伪节点。
- `敏感服务`：手动选定节点；配合 `store-selected` 持久保存。
- `直连优先`：手动选择 `DIRECT` 或 `日常代理`，默认 `DIRECT`。
- `广告拦截`：手动选择 `REJECT` 或 `DIRECT`，默认 `REJECT`。

旧地址 [`clash/clash-verge-merge.yaml`](clash/clash-verge-merge.yaml) 继续保留，但属于 Legacy 兼容模式：它要求机场已有 `PROXY` 组，不提供独立敏感节点组，直连优先与最终兜底均为 `DIRECT`。

## mihomo rule-provider

[`clash/rule-provider.yaml`](clash/rule-provider.yaml) 是带 `payload:` 的通用海外代理规则 provider。广告、直连、敏感服务和直连优先应分别引用 `rules/reject.list`、`rules/direct.list`、`rules/sensitive.list`、`rules/direct-preferred.list`，并显式设置 `behavior: classical`、`format: text`；不要把不同策略塞进一个 `RULE-SET`。

## Shadowrocket

将以下 URL 作为配置订阅导入：

```text
https://raw.githubusercontent.com/Luca4Don3/clash-rules/master/shadowrocket/shadowrocket.conf
```

首次导入后检查：

1. `日常代理` 和 `敏感服务` 中出现真实订阅节点，且没有流量/到期提示节点。
2. 为 `敏感服务` 手动选择一个固定节点。
3. `直连优先` 默认显示 `DIRECT`，`广告拦截` 默认显示 `REJECT`。
4. 规则末尾是 `FINAL,DIRECT`；访问国内站点与敏感服务各验证一次路由。

Shadowrocket 使用 `doh.pub` 和 `dns.alidns.com` DoH，`223.5.5.5`、`119.29.29.29` 仅作 bootstrap/fallback。`shadowrocket/geosite/sensitive.list` 与其他 geosite 产物一样由政策源生成；geosite 域名正则无法可靠转换成 Shadowrocket 域名规则时会跳过，并在生成日志与文件头报告数量，不会用 `URL-REGEX` 冒充域名规则。

## 规则生成

唯一政策源是 [`rules/policy.list`](rules/policy.list)，目标只允许 `REJECT`、`DIRECT`、`SENSITIVE`、`DIRECT-PREFERRED`、`PROXY`。生成命令：

```bash
python3 tools/gen-shadowrocket.py
python3 -m unittest discover -s tests -v
python3 tools/check-diff.py
# 本地集成验证还需要 Node.js 与 .temp/mihomo：
python3 tools/test-integration.py
```

下载固定使用失败检测、重试、连接超时和总超时；[`rules/sources.json`](rules/sources.json) 记录上游 URL、版本、每项 SHA-256 和整体 `snapshot_sha256`。离线生成只代表该清单对应的快照，CI 才会按 `latest` 重新抓取；CI 只暂存明确列出的生成产物。

规则顺序固定为：广告/恶意拦截 → 私网 → 敏感服务 → 国内定制 → GEOSITE CN → 直连优先 → 普通海外代理 → GEOIP CN → DIRECT。当前 CN 分类优先于普通海外代理，因此 `.cn` 海外服务需要显式前置例外，不能直接全局调换顺序。私网规则强制使用 `DIRECT`；URLhaus 生成的 IP 规则会排除与这些私网/特殊地址重叠的条目。火山引擎中国站是用户指定的强制直连例外，置于广告规则之前，避免被上游广告条目（如 `mssdk.volces.com`）遮蔽；国际站 `byteplus.com` 仍使用敏感服务策略。

## 数据来源

数据来自 MetaCubeX/meta-rules-dat、v2fly/domain-list-community、privacy-protection-tools/anti-AD、AdGuardTeam/AdGuardSDNSFilter、Cats-Team/AdRules 与 abuse.ch/URLhaus。URLhaus 的 plain-text 是逐 URL IOC；当前生成器只提取可安全表示的主机名/IP，并在生成日志中保留跳过项，若要更低误杀应改用其需要认证的 hostfile/RPZ 数据集。
