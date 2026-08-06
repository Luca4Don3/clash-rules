# 分流规则

一套开箱即用的分流规则(Clash / Shadowrocket),覆盖日常上网的大部分场景:

- **海外网站自动走代理**:Google、YouTube、ChatGPT、GitHub、Netflix、X/Twitter、Discord、Telegram 等
- **国内网站自动直连**:淘宝、京东、B站、知乎、国内 AI(DeepSeek/Kimi)、国内邮箱等,不绕路
- **智能兜底**:不确定的网站,先直连,连不上自动切代理
- **广告过滤**:屏蔽常见国内广告/统计域名,不影响网站正常功能
- **封禁风险保护**:对封大陆 IP 的平台(AI/加密/金融/券商等)强制走代理,避免风控

## 快速开始(推荐)

**Clash Verge / Clash Verge Rev 用户**,30 秒完成:

1. 打开 Clash Verge → **设置** → **全局扩展** → **从 URL 添加**
2. 粘贴:

```
https://raw.githubusercontent.com/Luca4Don3/clash-rules/master/clash-verge-merge.yaml
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
    url: https://raw.githubusercontent.com/Luca4Don3/clash-rules/master/rule-provider.yaml
    path: ./rules/universal.yaml
    interval: 86400
```

在 `rules:` 最前面加一行:

```yaml
  - RULE-SET,universal,直连优先
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

## 提示

- 兜底策略:建议将订阅自带 `rules` 末尾的 `MATCH` 指向 `直连优先` 组,体验最佳
