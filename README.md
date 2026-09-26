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

Shadowrocket 使用 `doh.pub` 和 `dns.alidns.com` DoH，`223.5.5.5`、`119.29.29.29` 仅作 bootstrap/fallback。`ipcn.list` 是仓库固定快照，后面的客户端 `GEOIP,CN` 是数据库回退，因此两条 CN IP 规则有意保留。`shadowrocket/geosite/*.list` 与其他 geosite 产物一样由政策源生成：普通条目按类型转成 `DOMAIN`/`DOMAIN-SUFFIX`/`DOMAIN-KEYWORD`，有限且安全的域名正则会展开为 `DOMAIN-SUFFIX`（例如 `(^|\.)18jmttios[0-9]{2}\.com$` 展开为 100 条），展开结果会用原正则二次校验并要求是合法多标签域名；含 `\d`/`\w`/`\S` 等不可枚举字符、重复上限过大或展开规模超限的表达式仍会跳过，并在生成日志与文件头报告数量，不会用 `URL-REGEX` 冒充域名规则。OpenAI、Netflix 与 Ookla 的关键动态正则由政策源中的窄 `DOMAIN-KEYWORD`/`DOMAIN-SUFFIX` 兜底；Google 的两条动态正则已由现有静态后缀完整覆盖。Clash 端直接使用原生 `GEOSITE`，不受展开结果影响。

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

规则顺序固定为：广告/恶意拦截 → 私网 → 敏感服务 → 国内定制 → GEOSITE CN → 直连优先 → 普通海外代理（含 `GEOSITE,geolocation-!cn` 末端兜底）→ GEOIP CN → DIRECT。当前 CN 分类优先于普通海外代理，因此 `.cn` 海外服务若要代理需要显式前置例外，不能直接全局调换顺序；当前未擅自增加 `.cn` 金融例外，以免未经确认改变流量路径。以当前快照计算，`GEOSITE,cn` 会遮蔽 `GEOSITE,geolocation-!cn` 的 217 个域名，其中绝大多数是被收录的中国镜像或国内站（`apple.xn--fiqs8s`、`steam.*.qtlglb.com`、`cnpmjs.org`、灰产盗版站），直连正确。已知仍有两组语义不一致待决策：`kimi.ai` 落直连而 `moonshot.ai`/`minimax.io` 走敏感服务；`alibabacloud.com.hk/tw/sg/au/my/co.in` 与 `alicloud.com` 落直连而 `alibabacloud.com` 走敏感服务。敏感服务整体位于 CN 之前，因此 `alibabacloud.com`、`bigo.tv`、`minimax.io`、`moonshot.ai`、`tencentcloud.com`、`z.ai`、`dashscope-intl.aliyuncs.com` 这 7 个国内可直连的域名仍强制走代理；其中 `dashscope-intl.aliyuncs.com` 被 `DOMAIN-SUFFIX,aliyuncs.com,DIRECT` 遮蔽属于有意例外（阿里云国际 API 走代理，aliyuncs.com 其余子域直连）。私网规则强制使用 `DIRECT`；URLhaus 生成的 IP 规则会排除与这些私网/特殊地址重叠的条目。火山引擎中国站是用户指定的强制直连例外，置于广告规则之前，避免被上游广告条目（如 `mssdk.volces.com`）遮蔽；该例外集合在生成器里以 `FORCE_DIRECT_DOMAINS` 为准，启动时校验它与政策源声明一致（缺项即报错），测试同时校验 `clash-verge-script.js` 内联的直连域名没有超出该集合，避免三处维护产生分叉；国际站 `byteplus.com` 仍使用敏感服务策略。

## 数据来源

数据来自 MetaCubeX/meta-rules-dat、v2fly/domain-list-community、privacy-protection-tools/anti-AD、AdGuardTeam/AdGuardSDNSFilter、Cats-Team/AdRules 与 abuse.ch/URLhaus。广告源按 2-of-3 交集生成，ABP `$important` 规则计入投票，`@@||host^` 例外会从投票中扣除；URLhaus 的 plain-text 是逐 URL IOC，当前生成器按精确主机输出 `DOMAIN`，不会把恶意子域提升成父域后扩大到整个站点，并保留带 `no-resolve` 的公网 IP 规则。以当前快照计，URLhaus 贡献 3,515 条精确域名与 13,990 条 `IP-CIDR,no-resolve`（占 `rules/reject.list` 的 12.5%），这些 IP 全部排除私网/回环/链路本地/保留/组播段且 0 条落在 `geoip` 的 CN 段，但仍属逐 URL 级 C2 观测：主机端口以 8080/8070 等非标准端口为主，被回收分配后存在与正常服务同 IP 的长期误杀面。若要进一步降低 IP 误杀，应改用其需要认证的 hostfile/RPZ 数据集。

## 交叉核验

对全部产物做过祖先级（父域）交叉核验，覆盖 98,296 个拦截后缀与 8 个 geosite 分类：广告与恶意域名对 `openai`、`anthropic`、`netflix`、`gfw` 的误杀为 0；被遮蔽的国内与海外条目都是广告 SDK 与遥测子域（`ipinyou.com`、`gvt2.com`、`cc-dt.com`、`anythinktech.com`），属预期拦截；`GEOSITE,category-ads-all` 中确含 3 个 OpenAI 遥测域名（`browser-intake-datadoghq.com`、`o33249.ingest.sentry.io`、`openai.qualtrics.com`），拦截它们同样符合预期。生成产物内部无重复行，`rules/sensitive.list` 与 `shadowrocket/geosite/sensitive.list` 交叠的 4 条（`chatgpt.com`、`oaistatic.com`、`oaiusercontent.com`、`sora.com`）是 geosite 与政策源同时声明的同一意图，保留作为上游变动时的护栏。
