# Clash 通用分流规则

可直接订阅/替换使用的 Clash 分流规则(无节点信息,出口用 PROXY/DIRECT/🌐 直连优先 关键字)。

## 用法

1. **替换订阅 rules**:Clash Verge → 订阅 → 右键 → 编辑文件,把 `rules:` 整段换成本文件 `rules:` 段;把 `🌐 直连优先` 组追加到 `proxy-groups:` 末尾。
2. **直接订阅**:将本文件 raw URL 作为订阅链接添加(需自行合并节点)。
3. **Clash Verge 全局扩展**:把 `rules:` 段内容放入 Merge 扩展的 `prepend-rules`。

## 策略

- 🚀 PROXY:AI/加密/金融/社交/流媒体/游戏/军事/短链等封 IP 平台(强制代理,不直连)
- 🌐 直连优先:GitHub/Steam/开发工具/学习/内容站/CDN(能直连就直连,不通自动切代理)
- ⚡ DIRECT:内网/Apple/国内 AI/国内邮箱/大陆平台(强制直连)
- 🚫 REJECT:纯广告/统计域名(不影响功能)
