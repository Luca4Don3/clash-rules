#!/usr/bin/env python3
"""
从 Clash 规则 + mihomo 官方 geosite/geoip 数据库生成 Shadowrocket 订阅配置。

产物:
  shadowrocket/shadowrocket.conf    Shadowrocket 完整配置(URL 订阅导入)
  shadowrocket/geosite/ads.list     广告域名规则集(RULE-SET 自动更新)
  shadowrocket/geosite/cn.list      中国大陆域名规则集(由 GEOSITE,cn 展开)
  shadowrocket/geosite/proxy.list   海外平台域名规则集(由所有 PROXY 的 GEOSITE 展开)
  shadowrocket/geosite/ipcn.list    中国大陆 IP-CIDR 规则集(由 geoip.dat CN 展开)

用法:
  python3 tools/gen-shadowrocket.py            # 自动下载最新 geosite.dat / geoip.dat
  python3 tools/gen-shadowrocket.py --offline  # 复用本地已下载的 dat 文件
  python3 tools/gen-shadowrocket.py --dat-dir /tmp
"""

import argparse
import os
import re
import sys
import urllib.request
from collections import Counter, OrderedDict

REPO = "Luca4Don3/clash-rules"
BRANCH = "master"
BASE_URL = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/shadowrocket/geosite"
DAT_RELEASES = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest"

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


def parse_site(buf):
    """geosite Site: field1=domain(string)"""
    i, n = 0, len(buf)
    while i < n:
        tag = buf[i]
        i += 1
        if tag == 0x0A:
            ln, i = parse_varint(buf, i)
            return buf[i : i + ln].decode("utf-8", "replace"), i + ln
        i += 1
    return "", i


def parse_geosite(buf):
    """geosite GeoSite: field1=country_code, field2=Domain 列表"""
    domains = []
    i, n = 0, len(buf)
    while i < n:
        tag = buf[i]
        i += 1
        if tag == 0x0A:  # country_code
            ln, i = parse_varint(buf, i)
            i += ln
        elif tag == 0x12:  # Domain
            ln, i = parse_varint(buf, i)
            domains.append(buf[i : i + ln])
            i += ln
        else:
            i += 1
    return domains


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


def parse_geoip(buf):
    """geoip GeoIP: field1=country_code, field2=CIDR 列表"""
    cidrs = []
    i, n = 0, len(buf)
    while i < n:
        tag = buf[i]
        i += 1
        if tag == 0x0A:
            ln, i = parse_varint(buf, i)
            i += ln
        elif tag == 0x12:
            ln, i = parse_varint(buf, i)
            cidrs.append(parse_cidr(buf[i : i + ln]))
            i += ln
        else:
            i += 1
    return cidrs


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


# ---------- geosite 条目 -> Shadowrocket 规则 ----------

def geosite_to_rule(typ, val):
    """返回 (rule_line) 或 None(无法转换)"""
    # 剥离 v2ray 属性(@xxx)
    if "@" in val:
        val = val.split("@", 1)[0]
    # 处理显式前缀(个别数据源可能有)
    for prefix, kind in (("regexp:", 1), ("full:", 3), ("domain:", 2), ("keyword:", 4), ("plain:", 0)):
        if val.startswith(prefix):
            typ, val = kind, val[len(prefix):]
            break
    val = val.strip().lstrip(".")
    if not val:
        return None
    if typ == TYPE_PLAIN or typ == TYPE_DOMAIN:
        # mihomo 语义:Plain 与 Domain 均为后缀匹配(含子域)
        return f"DOMAIN-SUFFIX,{val}"
    if typ == TYPE_FULL:
        return f"DOMAIN,{val}"
    if typ == TYPE_REGEX:
        return f"URL-REGEX,{val}"
    return None


def update_clash_platform_extra(repo_root, cats):
    entries = cats.get("CATEGORY-PORN", [])
    if not entries:
        print("  [警告] geosite.dat 中无 CATEGORY-PORN 分类,跳过平台域名补充")
        return
    extra = set()
    for typ, val in entries:
        if "@" in val:
            val = val.split("@", 1)[0]
        val = val.strip().lstrip(".")
        if not val:
            continue
        if typ in (TYPE_PLAIN, TYPE_DOMAIN):
            r = f"DOMAIN-SUFFIX,{val},PROXY"
        elif typ == TYPE_FULL:
            r = f"DOMAIN,{val},PROXY"
        elif typ == TYPE_REGEX:
            r = f"DOMAIN-REGEX,{val},PROXY"
        else:
            continue
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

    # rule-provider.yaml 每行一个 "- RULE";merge 的 prepend-rules 为嵌套列表 "  - - RULE"
    patch(os.path.join(repo_root, "rule-provider.yaml"), "", "- ")
    patch(os.path.join(repo_root, "clash-verge-merge.yaml"), "  ", "- - ")


# ---------- 主流程 ----------

def load_dat(path, parser_cls):
    with open(path, "rb") as f:
        return parser_cls(f.read())


def download(url, dest):
    if os.path.exists(dest):
        print(f"  复用 {dest} ({os.path.getsize(dest) // 1024} KB)")
        return
    print(f"  下载 {url}")
    urllib.request.urlretrieve(url, dest)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="不下载 dat,复用本地文件")
    ap.add_argument("--dat-dir", default=".", help="dat 文件所在目录")
    args = ap.parse_args()

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dat_dir = os.path.abspath(args.dat_dir)
    geosite_path = os.path.join(dat_dir, "geosite.dat")
    geoip_path = os.path.join(dat_dir, "geoip.dat")

    print("== 1/5 准备 geosite/geoip 数据 ==")
    if not args.offline:
        download(f"{DAT_RELEASES}/geosite.dat", geosite_path)
        download(f"{DAT_RELEASES}/geoip.dat", geoip_path)

    print("== 2/5 解析 geosite.dat ==")
    cats = {}
    data = open(geosite_path, "rb").read()
    for blob in parse_list_file(data):
        cc, domains = parse_geosite_full(blob)
        if cc:
            cats[cc] = domains
    print(f"  共 {len(cats)} 个分类")

    print("== 3/5 生成规则集文件 ==")
    out_dir = os.path.join(repo_root, "shadowrocket", "geosite")
    os.makedirs(out_dir, exist_ok=True)

    def expand(cat_names, warn=True):
        rules = set()
        missing = []
        for name in cat_names:
            dat_name = GEOSITE_MAP.get(name)
            entries = cats.get(dat_name, [])
            if not entries:
                missing.append(name)
                continue
            for typ, val in entries:
                r = geosite_to_rule(typ, val)
                if r:
                    rules.add(r)
        if warn and missing:
            print(f"  [警告] 以下分类在 geosite.dat 中不存在: {missing}")
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

    print("== 4/5 生成 ipcn.list(geoip.dat CN) ==")
    ipcn = set()
    data = open(geoip_path, "rb").read()
    for blob in parse_list_file(data):
        cc, cidrs = parse_geoip_full(blob)
        if cc != "CN":
            continue
        for ipb, prefix in cidrs:
            try:
                import ipaddress
                ip = ipaddress.ip_address(ipb)
                if ip.version == 4:
                    ipcn.add(f"IP-CIDR,{ip}/{prefix}")
                else:
                    ipcn.add(f"IP-CIDR6,{ip}/{prefix}")
            except ValueError:
                continue
    print(f"  ipcn.list:  {len(ipcn):>7} 条")
    with open(os.path.join(out_dir, "ipcn.list"), "w") as f:
        f.write("# 中国大陆 IP 段(由 geoip.dat CN 展开,自动更新)\n")
        f.write("\n".join(sorted(ipcn)) + "\n")

    print("== 4.5/5 同步 Clash 平台域名补充 ==")
    update_clash_platform_extra(repo_root, cats)

    print("== 5/5 生成 shadowrocket.conf ==")
    rule_path = os.path.join(repo_root, "rule-provider.yaml")
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
                continue  # Clash 内嵌展开块由 proxy.list 规则集覆盖,不转入 conf
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
    conf_lines.append("Proxy = select,♻️ 自动选择,🚀 手动切换")
    conf_lines.append("♻️ 自动选择 = url-test,Proxy,url=http://www.gstatic.com/generate_204,interval=300,tolerance=50")
    conf_lines.append("🚀 手动切换 = select,♻️ 自动选择")
    conf_lines.append("直连优先 = fallback,DIRECT,Proxy,url=http://connect.rom.miui.com/generate_204,interval=300")
    conf_lines.append("")
    conf_lines.append("[Rule]")

    section = ""
    proxy_rule_emitted = False
    # 预扫描:找到最后一个 PROXY GEOSITE 的位置,proxy.list 合并后放在那里
    last_proxy_geosite = None
    for idx, parts in enumerate(rules):
        if parts[0] == "GEOSITE" and parts[1] in PROXY_CATS:
            last_proxy_geosite = idx

    for idx, parts in enumerate(rules):
        kind = parts[0]
        if kind == "GEOSITE":
            name = parts[1]
            if name in ADS_CATS:
                conf_lines.append(f"RULE-SET,{BASE_URL}/ads.list,REJECT")
            elif name in CN_CATS:
                conf_lines.append(f"RULE-SET,{BASE_URL}/cn.list,DIRECT")
            elif name in PROXY_CATS:
                # 所有 PROXY 平台分类合并为单个规则集,放在最后一个出现的位置
                if idx == last_proxy_geosite:
                    conf_lines.append(f"RULE-SET,{BASE_URL}/proxy.list,Proxy")
            else:
                print(f"  [警告] 未映射的 GEOSITE 分类: {name},已跳过")
            continue
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

    # 统计
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
              os.path.join(out_dir, "proxy.list"), os.path.join(out_dir, "ipcn.list")):
        print(f"  {os.path.relpath(p, repo_root)}  ({os.path.getsize(p) // 1024} KB)")


def parse_geosite_full(buf):
    """返回 (country_code, [(typ, val), ...])"""
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
    """返回 (country_code, [(ip_bytes, prefix), ...])"""
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


if __name__ == "__main__":
    main()
