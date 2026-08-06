# Clash 通用分流规则(可订阅)

无节点信息,出口使用 PROXY / DIRECT / 直连优先 / REJECT 关键字的通用分流规则。

## 订阅方式(推荐)

### 方式一:Clash Verge 全局扩展(最简单,订阅更新不丢)

1. 设置 → 全局扩展 → 从 URL 添加
2. URL:`https://raw.githubusercontent.com/Luca4Don3/clash-rules/master/clash-verge-merge.yaml`
3. 保存后自动生效;机场订阅更新不影响规则

### 方式二:mihomo rule-provider(标准订阅)

在订阅配置中加:

```yaml
rule-providers:
  universal:
    type: http
    behavior: classical
    url: https://raw.githubusercontent.com/Luca4Don3/clash-rules/master/rule-provider.yaml
    path: ./rules/universal.yaml
    interval: 86400
```

并将 `rules:` 中加一行(放在订阅自带规则之前):

```yaml
  - RULE-SET,universal,直连优先
```

### 方式三:直接替换订阅文件的 rules 段

下载 `clash-rules.yaml`,把 `rules:` 整段替换进订阅配置,并把 `直连优先` 组追加到 `proxy-groups:`。

## 兜底说明

- 方式一/二 的兜底:建议把订阅自带 `rules` 末尾的 `MATCH` 指向 `直连优先` 组(或按需用 PROXY/DIRECT)
- `clash-rules.yaml` 已含完整兜底(`MATCH,直连优先`),直接替换最省心

## 策略

- **PROXY**:AI/加密/金融/社交/流媒体/游戏/军事/短链等封 IP 平台(强制代理,不直连)
- **直连优先**:GitHub/Steam/开发工具/学习/内容站/CDN(能直连就直连,不通自动切代理)
- **DIRECT**:内网/Apple/国内 AI/国内邮箱/大陆平台(强制直连)
- **REJECT**:纯广告/统计域名(不影响功能)
