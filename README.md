# 分流规则

一套开箱即用的分流规则(Clash / Shadowrocket),覆盖日常上网的大部分场景:

- **海外网站自动走代理**:Google、YouTube、ChatGPT、GitHub、Netflix、X/Twitter、Discord、Telegram 等
- **国内网站自动直连**:淘宝、京东、B站、知乎、国内 AI(DeepSeek/Kimi)、国内邮箱等,不绕路
- **策略兜底**:不确定的网站,先直连,连不上自动切代理
- **广告过滤**:自维护精确规则 + 多源交叉验证的大列表兜底,屏蔽常见广告/统计/恶意域名,不影响网站正常功能
- **封禁风险保护**:对封大陆 IP 的平台(AI/加密/金融/券商等)强制走代理,避免风控

## 目录结构

```
clash/                 Clash 系配置
  clash-verge-merge.yaml   Clash Verge 全局扩展
  rule-provider.yaml       mihomo rule-provider
shadowrocket/          Shadowrocket 配置与规则集
  shadowrocket.conf        完整配置(订阅导入)
  geosite/                 geosite 展开的规则集(ads/cn/proxy/ipcn)
rules/                 多端共用的补充规则集
  ads-extra.list          广告域名补充(多源交叉验证)
  malware.list            恶意/诈骗/钓鱼域名
tools/                 生成脚本
```

## 快速开始(推荐)

**Clash Verge / Clash Verge Rev 用户**,30 秒完成:

1. 打开 Clash Verge → **设置** → **全局扩展** → **从 URL 添加**
2. 粘贴:

```
https://raw.githubusercontent.com/Luca4Don3/clash-rules/master/clash/clash-verge-merge.yaml
```

3. 保存即生效。之后机场订阅怎么更新,规则都不会丢。

## 其他方式

**mihomo(Clash Meta 内核)rule-provider**

在订阅配置中加:

```yaml
rule-providers:
  universal:
    type: http
    behavior: classical
    url: https://raw.githubusercontent.com/Luca4Don3/clash-rules/master/clash/rule-provider.yaml
    path: ./rules/universal.yaml
    interval: 86400
  ads-extra:
    type: http
    behavior: classical
    url: https://raw.githubusercontent.com/Luca4Don3/clash-rules/master/rules/ads-extra.list
    path: ./rules/ads-extra.yaml
    interval: 86400
```

在 `rules:` 最前面加两行:

```yaml
  - RULE-SET,universal,直连优先
  - RULE-SET,ads-extra,REJECT
```

## Shadowrocket(iOS)

iPhone 用户(小火箭),30 秒完成:

1. 打开 Shadowrocket → **配置** → 右上角 **+** → 类型选 **Subscribe(订阅)**
2. 粘贴:

```
https://raw.githubusercontent.com/Luca4Don3/clash-rules/master/shadowrocket/shadowrocket.conf
```

3. 保存并切换到该配置,完成。机场订阅怎么更新,规则都不会丢。

规则集(`RULE-SET`)在刷新配置时自动更新,无需手动维护。策略说明:

- **Proxy**:默认自动选择延迟最低的节点,也可以切到手动模式自己挑
- **直连优先**:GitHub、Steam、图库等站点先直连,连不上自动走代理

> 提示:首次导入需要设备能访问 GitHub。若规则集更新失败,把配置里的
> `raw.githubusercontent.com` 换成镜像 `cdn.jsdelivr.net/gh/Luca4Don3/clash-rules@master` 即可。

## 致谢

规则数据引用以下开源项目,特此感谢:

- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat):geosite / geoip 数据库,规则集的数据源
- [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community):geosite 域名的社区维护来源
- [privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD):广告域名列表
- [AdGuardTeam/AdGuardSDNSFilter](https://github.com/AdguardTeam/AdguardSDNSFilter):AdGuard DNS filter 广告列表
- [Cats-Team/AdRules](https://github.com/Cats-Team/AdRules):乘风广告规则
- [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists):诈骗域名列表
- [abuse.ch/URLhaus](https://urlhaus.abuse.ch):恶意软件分发域名列表

其中广告域名采用多源交叉验证:仅收录至少两个独立源共现的域名,并设有核心域名保护名单,上游出现异常时自动拦截。

## 提示

- 兜底策略:建议将订阅自带 `rules` 末尾的 `MATCH` 指向 `直连优先` 组,体验最佳
- 广告规则分两层:自维护精确规则(最前)+ 社区大列表兜底,如需调整误杀,优先改自维护段
