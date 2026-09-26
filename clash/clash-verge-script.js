// Clash Verge Rev 全局扩展脚本。保留机场节点、provider、策略组和 DNS。
const RAW = "https://raw.githubusercontent.com/Luca4Don3/clash-rules/master";
const FILTER = "(?i)^(?!.*(?:流量|到期|剩余|官网|套餐|Traffic|Expire|Website)).+$";

function provider(name) {
  return {
    type: "http",
    behavior: "classical",
    format: "text",
    url: `${RAW}/rules/${name}.list`,
    path: `./rules/${name}.list`,
    interval: 86400,
  };
}

function upsertGroup(groups, group) {
  const index = groups.findIndex((item) => item && item.name === group.name);
  if (index === -1) groups.push(group);
  else groups[index] = group;
}

function main(config) {
  config["rule-providers"] = config["rule-providers"] || {};
  for (const name of ["reject", "direct", "sensitive", "direct-preferred", "proxy"]) {
    config["rule-providers"][name] = provider(name);
  }

  const groups = Array.isArray(config["proxy-groups"]) ? config["proxy-groups"] : [];
  upsertGroup(groups, {
    name: "日常代理", type: "url-test", "include-all": true,
    "exclude-filter": FILTER, url: "http://www.gstatic.com/generate_204",
    interval: 300, tolerance: 50,
  });
  upsertGroup(groups, {
    name: "敏感服务", type: "select", "include-all": true,
    "exclude-filter": FILTER,
  });
  upsertGroup(groups, { name: "直连优先", type: "select", proxies: ["DIRECT", "日常代理"] });
  upsertGroup(groups, { name: "广告拦截", type: "select", proxies: ["REJECT", "DIRECT"] });
  config["proxy-groups"] = groups;
  config.profile = Object.assign({}, config.profile, { "store-selected": true });

  config.rules = [
    // 用户明确要求的火山引擎强制直连例外，必须先于广告上游规则。
    "DOMAIN-SUFFIX,volcengine.com,DIRECT",
    "DOMAIN-SUFFIX,volcengine.net,DIRECT",
    "DOMAIN-SUFFIX,volcengineapi.com,DIRECT",
    "DOMAIN-SUFFIX,volcengine-api.com,DIRECT",
    "DOMAIN-SUFFIX,volces.com,DIRECT",
    "DOMAIN-SUFFIX,volceapi.com,DIRECT",
    "DOMAIN-SUFFIX,volccdn.com,DIRECT",
    "DOMAIN-SUFFIX,volcdns.com,DIRECT",
    "DOMAIN-SUFFIX,volcvideo.com,DIRECT",
    "DOMAIN-SUFFIX,volcimagex.com,DIRECT",
    "DOMAIN-SUFFIX,byteimg.com,DIRECT",
    "DOMAIN-SUFFIX,ibytedtos.com,DIRECT",
    "RULE-SET,reject,广告拦截",
    "GEOSITE,category-ads-all,广告拦截",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
    "IP-CIDR,240.0.0.0/4,DIRECT,no-resolve",
    "IP-CIDR6,::1/128,DIRECT,no-resolve",
    "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
    "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
    "IP-CIDR6,ff00::/8,DIRECT,no-resolve",
    "RULE-SET,sensitive,敏感服务",
    "GEOSITE,openai,敏感服务",
    "GEOSITE,anthropic,敏感服务",
    "RULE-SET,direct,DIRECT",
    "GEOSITE,cn,DIRECT",
    "RULE-SET,direct-preferred,直连优先",
    "RULE-SET,proxy,日常代理",
    "GEOSITE,geolocation-!cn,日常代理",
    "GEOSITE,gfw,日常代理",
    "GEOSITE,google,日常代理",
    "GEOSITE,youtube,日常代理",
    "GEOSITE,telegram,日常代理",
    "GEOSITE,facebook,日常代理",
    "GEOSITE,twitter,日常代理",
    "GEOSITE,instagram,日常代理",
    "GEOSITE,whatsapp,日常代理",
    "GEOSITE,discord,日常代理",
    "GEOSITE,reddit,日常代理",
    "GEOSITE,netflix,日常代理",
    "GEOSITE,spotify,日常代理",
    "GEOSITE,twitch,日常代理",
    "GEOSITE,category-porn,日常代理",
    "GEOIP,CN,DIRECT,no-resolve",
    "MATCH,DIRECT",
  ];
  return config;
}
