#!/usr/bin/env python3
"""
从 Clash 规则 + mihomo 官方 geosite/geoip 数据库 + anti-AD 生成全端订阅配置。

产物:
  clash/rule-provider.yaml        mihomo rule-provider(含平台域名补充)
  clash/clash-verge-merge.yaml    Clash Verge 全局扩展(含平台域名补充)
  shadowrocket/shadowrocket.conf  Shadowrocket 完整配置(URL 订阅导入)
  shadowrocket/geosite/ads.list   广告域名规则集(category-ads-all 展开)
  shadowrocket/geosite/cn.list    中国大陆域名规则集(GEOSITE,cn 展开)
  shadowrocket/geosite/proxy.list 海外平台域名规则集(GEOSITE 平台分类展开)
  shadowrocket/geosite/ipcn.list  中国大陆 IP-CIDR 规则集(geoip.dat CN 展开)
  rules/ads-extra.list            广告域名补充规则集(anti-AD,多端共用)

用法:
  python3 tools/gen-shadowrocket.py            # 自动下载最新数据源
  python3 tools/gen-shadowrocket.py --offline  # 复用 --dat-dir 下已下载的数据源
"""

import argparse
import os
import sys
import urllib.request
from collections import Counter

REPO = "Luca4Don3/clash-rules"
BRANCH = "master"
BASE_URL = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/shadowrocket/geosite"
RULES_URL = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/rules"
DAT_RELEASES = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest"
ANTI_AD_URL = "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt"

# rule-provider.yaml 中 GEOSITE 分类 -> geosite.dat 分类名(大写)
GEOSITE_MAP = {
    "category-ads-all": "CATEGORY-ADS-ALL",
    "cn": "CN",
    "category-porn": "CATEGORY-PORN",
    "google": "GOOGLE",
    "microsoft": "MICROSOFT",
    "telegram": "TELEGRAM",
    "facebook": "FACEBOOK",
    "twitter": "TWITTER",
    "instagram": "INSTAGRAM",
    "whatsapp": "WHATSAPP",
    "discord": "DISCORD",
    "reddit": "REDDIT",
    "linkedin": "LINKEDIN",
    "pinterest": "PINTEREST",
    "tumblr": "TUMBLR",
    "tiktok": "TIKTOK",
    "quora": "QUORA",
    "medium": "MEDIUM",
    "youtube": "YOUTUBE",
    "netflix": "NETFLIX",
    "spotify": "SPOTIFY",
    "twitch": "TWITCH",
    "vimeo": "VIMEO",
    "dailymotion": "DAILYMOTION",
    "epicgames": "EPICGAMES",
    "amazon": "AMAZON",
    "ebay": "EBAY",
    "paypal": "PAYPAL",
    "cloudflare": "CLOUDFLARE",
    "openai": "OPENAI",
    "anthropic": "ANTHROPIC",
    "perplexity": "PERPLEXITY",
    "huggingface": "HUGGINGFACE",
    "jetbrains": "JETBRAINS",
    "gitlab": "GITLAB",
    "xbox": "XBOX",
    "nintendo": "NINTENDO",
    "sony": "SONY",
    "blizzard": "BLIZZARD",
    "gog": "GOG",
    "jable": "JABLE",
    "category-media": "CATEGORY-MEDIA",
    "category-finance": "CATEGORY-FINANCE",
    "category-dev": "CATEGORY-DEV",
    "category-games": "CATEGORY-GAMES",
    "gfw": "GFW",
}

# geosite Domain 类型(与 v2ray proto 一致)
TYPE_PLAIN, TYPE_REGEX, TYPE_DOMAIN, TYPE_FULL = 0, 1, 2, 3

# 策略名映射:Clash -> Shadowrocket
POLICY_MAP = {"REJECT": "REJECT", "DIRECT": "DIRECT", "PROXY": "Proxy", "直连优先": "直连优先"}

# Clash 文件中的平台域名补充块标记(自动生成,生成 conf 时跳过)
EXTRA_BEGIN = "# ===== 平台域名补充(自动生成,请勿手改)====="
EXTRA_END = "# ===== 平台域名补充结束 ====="

# 需要展开成独立规则集的 GEOSITE 分类
ADS_CATS = {"category-ads-all"}
CN_CATS = {"cn"}
PROXY_CATS = {c for c in GEOSITE_MAP if c not in ADS_CATS | CN_CATS}


# ---------- protobuf 解析(v2ray geosite / geoip 格式) ----------

def parse_varint(buf, i):
    val = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7


def parse_domain(buf):
    """geosite Domain: field1=type(enum), field2=value(string)"""
    typ, val = TYPE_PLAIN, ""
    i, n = 0, len(buf)
    while i < n:
        tag = buf[i]
        i += 1
        if tag == 0x08:
            typ, i = parse_varint(buf, i)
        elif tag == 0x12:
            ln, i = parse_varint(buf, i)
            val = buf[i : i + ln].decode("utf-8", "replace")
            i += ln
        else:
            i += 1
    return typ, val


def parse_cidr(buf):
    """geoip CIDR: field1=ip(bytes), field2=prefix(varint)"""
    ip_bytes, prefix = b"", 0
    i, n = 0, len(buf)
    while i < n:
        tag = buf[i]
        i += 1
        if tag == 0x0A:
            ln, i = parse_varint(buf, i)
            ip_bytes = buf[i : i + ln]
            i += ln
        elif tag == 0x10:
            prefix, i = parse_varint(buf, i)
        else:
            i += 1
    return ip_bytes, prefix


def parse_geosite_full(buf):
    """geosite GeoSite: field1=country_code, field2=Domain 列表"""
    cc = None
    domains = []
    i, n = 0, len(buf)
    while i < n:
        tag = buf[i]
        i += 1
        if tag == 0x0A:
            ln, i = parse_varint(buf, i)
            cc = buf[i : i + ln].decode("utf-8", "replace")
            i += ln
        elif tag == 0x12:
            ln, i = parse_varint(buf, i)
            domains.append(parse_domain(buf[i : i + ln]))
            i += ln
        else:
            i += 1
    return cc, domains


def parse_geoip_full(buf):
    """geoip GeoIP: field1=country_code, field2=CIDR 列表"""
    cc = None
    cidrs = []
    i, n = 0, len(buf)
    while i < n:
        tag = buf[i]
        i += 1
        if tag == 0x0A:
            ln, i = parse_varint(buf, i)
            cc = buf[i : i + ln].decode("utf-8", "replace")
            i += ln
        elif tag == 0x12:
            ln, i = parse_varint(buf, i)
            cidrs.append(parse_cidr(buf[i : i + ln]))
            i += ln
        else:
            i += 1
    return cc, cidrs


def parse_list_file(buf):
    """顶层列表: field1 = 每条记录"""
    records = []
    i, n = 0, len(buf)
    while i < n:
        if buf[i] == 0x0A:
            ln, i2 = parse_varint(buf, i + 1)
            records.append(buf[i2 : i2 + ln])
            i = i2 + ln
        else:
            i += 1
    return records


def load_geosite_cats(path):
    cats = {}
    data = open(path, "rb").read()
    for blob in parse_list_file(data):
        cc, domains = parse_geosite_full(blob)
        if cc:
            cats[cc] = domains
    return cats


def load_geoip_cn(path):
    cn = []
    data = open(path, "rb").read()
    for blob in parse_list_file(data):
        cc, cidrs = parse_geoip_full(blob)
        if cc == "CN":
            cn.extend(cidrs)
    return cn


# ---------- geosite 条目 -> Shadowrocket 规则 ----------

def geosite_to_rule(typ, val):
    """返回规则行或 None(无法转换)"""
    if "@" in val:
        val = val.split("@", 1)[0]
    for prefix, kind in (("regexp:", 1), ("full:", 3), ("domain:", 2), ("keyword:", 4), ("plain:", 0)):
        if val.startswith(prefix):
            typ, val = kind, val[len(prefix) :]
            break
    val = val.strip().lstrip(".")
    if not val:
        return None
    if typ in (TYPE_PLAIN, TYPE_DOMAIN):
        return f"DOMAIN-SUFFIX,{val}"
    if typ == TYPE_FULL:
        return f"DOMAIN,{val}"
    if typ == TYPE_REGEX:
        return f"URL-REGEX,{val}"
    return None


def geosite_to_clash_rule(typ, val, policy):
    """Clash 规则行(用于平台域名补充展开)"""
    if "@" in val:
        val = val.split("@", 1)[0]
    val = val.strip().lstrip(".")
    if not val:
        return None
    if typ in (TYPE_PLAIN, TYPE_DOMAIN):
        return f"DOMAIN-SUFFIX,{val},{policy}"
    if typ == TYPE_FULL:
        return f"DOMAIN,{val},{policy}"
    if typ == TYPE_REGEX:
        return f"DOMAIN-REGEX,{val},{policy}"
    return None


# ---------- anti-AD 解析 ----------

def load_anti_ad(path):
    """解析 anti-AD domains.txt,父域已在集合中的子域去掉"""
    domains = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            d = line.strip().lower()
            if not d or d.startswith("#"):
                continue
            if not all(c.isalnum() or c in ".-" for c in d):
                continue
            domains.add(d)
    kept = {d for d in domains if "." not in d or d.split(".", 1)[1] not in domains}
    return sorted(kept)


# ---------- 下载 ----------

def download(url, dest):
    if os.path.exists(dest):
        print(f"  复用 {dest} ({os.path.getsize(dest) // 1024} KB)")
        return
    print(f"  下载 {url}")
    urllib.request.urlretrieve(url, dest)


# ---------- Clash 文件补丁 ----------

def patch_clash_platform_extra(repo_root, cats):
    """把该平台补充分类展开为普通域名,混入两个 Clash 文件的平台段(gfw 之后)。
    幂等:已存在则整体替换,并清理旧的分类行。"""
    entries = cats.get("CATEGORY-PORN", [])
    if not entries:
        print("  [警告] geosite.dat 中无 CATEGORY-PORN 分类,跳过平台域名补充")
        return
    extra = set()
    for typ, val in entries:
        r = geosite_to_clash_rule(typ, val, "PROXY")
        if r:
            extra.add(r)
    extra = sorted(extra)

    def patch(path, indent, dash):
        with open(path, encoding="utf-8") as f:
            lines = f.read().split("\n")
        out, in_extra, inserted = [], False, False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(EXTRA_BEGIN):
                in_extra = True
                continue
            if stripped.startswith(EXTRA_END):
                in_extra = False
                continue
            if in_extra:
                continue
            if stripped.startswith("-") and "category-porn" in stripped:
                continue
            out.append(line)
            if "GEOSITE,gfw,PROXY" in stripped and not inserted:
                out.append(indent + EXTRA_BEGIN)
                out.extend(indent + dash + r for r in extra)
                out.append(indent + EXTRA_END)
                inserted = True
        if not inserted:
            print(f"  [警告] {path}: 未找到 GEOSITE,gfw 锚点,平台域名补充未插入")
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        print(f"  {path}: 平台域名补充 {len(extra)} 行")

    clash_dir = os.path.join(repo_root, "clash")
    patch(os.path.join(clash_dir, "rule-provider.yaml"), "", "- ")
    patch(os.path.join(clash_dir, "clash-verge-merge.yaml"), "  ", "- - ")


def patch_clash_ads_extra(repo_root):
    """给两个 Clash 文件注入 anti-AD 补充规则集引用。幂等。"""
    ads_rule = "RULE-SET,ads-extra,REJECT"
    anchor = "GEOSITE,category-ads-all,REJECT"

    def hit(line):
        return anchor in line

    # rule-provider.yaml:在广告分类行后插入
    path = os.path.join(repo_root, "clash", "rule-provider.yaml")
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    if any("RULE-SET,ads-extra,REJECT" in line for line in lines):
        print(f"  {path}: ads-extra 已存在")
    else:
        out = []
        for line in lines:
            out.append(line)
            if hit(line):
                out.append(f"- {ads_rule}")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        print(f"  {path}: 已注入 {ads_rule}")
    # clash-verge-merge.yaml:注入 prepend-rule-providers + 规则行
    path = os.path.join(repo_root, "clash", "clash-verge-merge.yaml")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if "ads-extra:" in text and ads_rule in text:
        print(f"  {path}: ads-extra 已存在")
        return
    provider_block = f"""prepend-rule-providers:
  ads-extra:
    type: http
    behavior: classical
    url: {RULES_URL}/ads-extra.list
    path: ./rules/ads-extra.yaml
    interval: 86400
"""
    lines = text.split("\n")
    # 清理已有注入(支持自愈重复/半注入状态)
    out, in_prov = [], False
    for line in lines:
        if line.strip() == "prepend-rule-providers:":
            in_prov = True
            continue
        if in_prov:
            if line.strip() == "prepend-rules:":
                in_prov = False
            else:
                continue
        if "RULE-SET,ads-extra,REJECT" in line:
            continue
        out.append(line)
    # 重新注入
    final, prov_emitted = [], False
    for line in out:
        if line.strip() == "prepend-rules:" and not prov_emitted:
            final.append(provider_block.rstrip("\n"))
            prov_emitted = True
        final.append(line)
        if hit(line):
            final.append(f"  - - {ads_rule}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(final) + "\n")
    print(f"  {path}: 已注入 ads-extra provider + 规则")


# ---------- 主流程 ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="不下载数据源,复用本地文件")
    ap.add_argument("--dat-dir", default=".", help="数据源文件所在目录")
    args = ap.parse_args()

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dat_dir = os.path.abspath(args.dat_dir)
    geosite_path = os.path.join(dat_dir, "geosite.dat")
    geoip_path = os.path.join(dat_dir, "geoip.dat")
    anti_ad_path = os.path.join(dat_dir, "anti-ad-domains.txt")

    print("== 1/6 准备数据源 ==")
    if not args.offline:
        download(f"{DAT_RELEASES}/geosite.dat", geosite_path)
        download(f"{DAT_RELEASES}/geoip.dat", geoip_path)
        download(ANTI_AD_URL, anti_ad_path)

    print("== 2/6 解析 geosite.dat ==")
    cats = load_geosite_cats(geosite_path)
    print(f"  共 {len(cats)} 个分类")

    print("== 3/6 生成 geosite 规则集 ==")
    out_dir = os.path.join(repo_root, "shadowrocket", "geosite")
    os.makedirs(out_dir, exist_ok=True)

    def expand(cat_names):
        rules = set()
        for name in cat_names:
            dat_name = GEOSITE_MAP.get(name)
            for typ, val in cats.get(dat_name, []):
                r = geosite_to_rule(typ, val)
                if r:
                    rules.add(r)
        return rules

    ads = expand(ADS_CATS)
    cn = expand(CN_CATS)
    proxy = expand(PROXY_CATS)
    print(f"  ads.list:   {len(ads):>7} 条")
    print(f"  cn.list:    {len(cn):>7} 条")
    print(f"  proxy.list: {len(proxy):>7} 条")
    with open(os.path.join(out_dir, "ads.list"), "w") as f:
        f.write("# 广告拦截域名(由 GEOSITE,category-ads-all 展开,自动更新)\n")
        f.write("\n".join(sorted(ads)) + "\n")
    with open(os.path.join(out_dir, "cn.list"), "w") as f:
        f.write("# 中国大陆域名(由 GEOSITE,cn 展开,自动更新)\n")
        f.write("\n".join(sorted(cn)) + "\n")
    with open(os.path.join(out_dir, "proxy.list"), "w") as f:
        f.write("# 海外平台域名(由 GEOSITE 平台分类展开,自动更新)\n")
        f.write("\n".join(sorted(proxy)) + "\n")

    print("== 4/6 生成 ipcn.list(geoip.dat CN) ==")
    ipcn = set()
    import ipaddress
    for ipb, prefix in load_geoip_cn(geoip_path):
        try:
            ip = ipaddress.ip_address(ipb)
        except ValueError:
            continue
        if ip.version == 4:
            ipcn.add(f"IP-CIDR,{ip}/{prefix}")
        else:
            ipcn.add(f"IP-CIDR6,{ip}/{prefix}")
    print(f"  ipcn.list:  {len(ipcn):>7} 条")
    with open(os.path.join(out_dir, "ipcn.list"), "w") as f:
        f.write("# 中国大陆 IP 段(由 geoip.dat CN 展开,自动更新)\n")
        f.write("\n".join(sorted(ipcn)) + "\n")

    print("== 5/6 生成 ads-extra.list(anti-AD) ==")
    rules_dir = os.path.join(repo_root, "rules")
    os.makedirs(rules_dir, exist_ok=True)
    ad_domains = load_anti_ad(anti_ad_path)
    print(f"  anti-AD 域名: {len(ad_domains)} 条")
    with open(os.path.join(rules_dir, "ads-extra.list"), "w") as f:
        f.write("# 广告域名补充(来自 anti-AD,自动更新)\n")
        f.write("\n".join(f"DOMAIN-SUFFIX,{d}" for d in ad_domains) + "\n")

    print("== 6/6 同步 Clash 文件 ==")
    patch_clash_platform_extra(repo_root, cats)
    patch_clash_ads_extra(repo_root)

    print("== 生成 shadowrocket.conf ==")
    rule_path = os.path.join(repo_root, "clash", "rule-provider.yaml")
    rules = []
    in_extra = False
    with open(rule_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith(EXTRA_BEGIN):
                in_extra = True
                continue
            if line.startswith(EXTRA_END):
                in_extra = False
                continue
            if in_extra:
                continue
            if line.startswith("#"):
                continue
            if not line.startswith("- "):
                continue
            body = line[2:].strip()
            parts = [p.strip() for p in body.split(",")]
            rules.append(parts)

    conf_lines = []
    conf_lines.append("# 分流规则 - Shadowrocket")
    conf_lines.append("# 用法:Shadowrocket -> 右上角 + -> 类型选 Subscribe(订阅) -> 粘贴本文件 URL")
    conf_lines.append("# 规则集(RULE-SET)每次刷新配置自动更新,无需手动维护")
    conf_lines.append("")
    conf_lines.append("[General]")
    conf_lines.append("dns-server = 223.5.5.5,119.29.29.29,8.8.8.8")
    conf_lines.append("ipv6 = true")
    conf_lines.append("")
    conf_lines.append("[Proxy Group]")
    conf_lines.append("Proxy = select,自动选择,手动切换")
    conf_lines.append("自动选择 = url-test,Proxy,url=http://www.gstatic.com/generate_204,interval=300,tolerance=50")
    conf_lines.append("手动切换 = select,自动选择")
    conf_lines.append("直连优先 = fallback,DIRECT,Proxy,url=http://connect.rom.miui.com/generate_204,interval=300")
    conf_lines.append("")
    conf_lines.append("[Rule]")

    last_proxy_geosite = None
    for idx, parts in enumerate(rules):
        if parts[0] == "GEOSITE" and parts[1] in PROXY_CATS:
            last_proxy_geosite = idx

    ads_extra_emitted = False
    for idx, parts in enumerate(rules):
        kind = parts[0]
        if kind == "GEOSITE":
            name = parts[1]
            if name in ADS_CATS:
                conf_lines.append(f"RULE-SET,{BASE_URL}/ads.list,REJECT")
                if not ads_extra_emitted:
                    conf_lines.append(f"RULE-SET,{RULES_URL}/ads-extra.list,REJECT")
                    ads_extra_emitted = True
            elif name in CN_CATS:
                conf_lines.append(f"RULE-SET,{BASE_URL}/cn.list,DIRECT")
            elif name in PROXY_CATS:
                if idx == last_proxy_geosite:
                    conf_lines.append(f"RULE-SET,{BASE_URL}/proxy.list,Proxy")
            else:
                print(f"  [警告] 未映射的 GEOSITE 分类: {name},已跳过")
            continue
        if kind == "RULE-SET":
            continue  # Clash provider 引用,Shadowrocket 由 GEOSITE 展开的完整 URL 规则集覆盖
        if kind == "MATCH":
            conf_lines.append(f"FINAL,{POLICY_MAP.get(parts[1], parts[1])}")
            continue
        if kind == "GEOIP" and parts[1] == "CN":
            conf_lines.append(f"RULE-SET,{BASE_URL}/ipcn.list,DIRECT")
            conf_lines.append(f"GEOIP,CN,{POLICY_MAP.get(parts[2], parts[2])}")
            continue
        sr_policy = POLICY_MAP.get(parts[-1], parts[-1])
        conf_lines.append(",".join(parts[:-1] + [sr_policy]))

    conf_path = os.path.join(repo_root, "shadowrocket", "shadowrocket.conf")
    with open(conf_path, "w", encoding="utf-8") as f:
        f.write("\n".join(conf_lines) + "\n")

    stat = Counter()
    for line in conf_lines:
        if line.startswith("RULE-SET"):
            stat["RULE-SET"] += 1
        elif line.startswith("FINAL"):
            stat["FINAL"] += 1
        elif line.startswith("GEOIP"):
            stat["GEOIP"] += 1
        elif line.startswith("IP-CIDR"):
            stat["IP-CIDR"] += 1
        elif line.startswith("DOMAIN-SUFFIX"):
            stat["DOMAIN-SUFFIX"] += 1
        elif line.startswith("DOMAIN,"):
            stat["DOMAIN"] += 1
    print(f"  本地 [Rule] 共 {len([l for l in conf_lines if l and not l.startswith(('#','[',' '))])} 行(含 RULE-SET)")
    print(f"  规则统计: {dict(stat)}")
    print(f"\n完成!产物:")
    for p in (conf_path, os.path.join(out_dir, "ads.list"), os.path.join(out_dir, "cn.list"),
              os.path.join(out_dir, "proxy.list"), os.path.join(out_dir, "ipcn.list"),
              os.path.join(rules_dir, "ads-extra.list")):
        print(f"  {os.path.relpath(p, repo_root)}  ({os.path.getsize(p) // 1024} KB)")


if __name__ == "__main__":
    main()
