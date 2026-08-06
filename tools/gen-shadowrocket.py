#!/usr/bin/env python3
"""
从 Clash 规则 + mihomo geosite/geoip 数据库 + 多个社区规则源生成全端订阅配置。

产物:
  clash/rule-provider.yaml        mihomo rule-provider(含平台域名补充)
  clash/clash-verge-merge.yaml    Clash Verge 全局扩展(含平台域名补充)
  shadowrocket/shadowrocket.conf  Shadowrocket 完整配置(URL 订阅导入)
  shadowrocket/geosite/ads.list   广告域名规则集(category-ads-all 展开)
  shadowrocket/geosite/cn.list    中国大陆域名规则集(GEOSITE,cn 展开)
  shadowrocket/geosite/proxy.list 海外平台域名规则集(GEOSITE 平台分类展开)
  shadowrocket/geosite/ipcn.list  中国大陆 IP-CIDR 规则集(geoip.dat CN 展开)
  rules/ads-extra.list            广告域名补充(多源交叉验证,多端共用)
  rules/malware.list              恶意/诈骗/钓鱼域名(多端共用)

用法:
  python3 tools/gen-shadowrocket.py            # 自动下载最新数据源
  python3 tools/gen-shadowrocket.py --offline  # 复用 --dat-dir 下已下载的数据源
"""

import argparse
import ipaddress
import os
import sys
import urllib.request
from collections import Counter

REPO = "Luca4Don3/clash-rules"
BRANCH = "master"
BASE_URL = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/shadowrocket/geosite"
RULES_URL = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/rules"
DAT_RELEASES = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest"

# 数据源: (文件名, 下载 URL, 最小字节数, 是否必备)
SOURCES = [
    ("geosite.dat", f"{DAT_RELEASES}/geosite.dat", 1_000_000, True),
    ("geoip.dat", f"{DAT_RELEASES}/geoip.dat", 5_000_000, True),
    ("anti-ad-domains.txt", "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt", 1_000_000, True),
    ("adguard-filter.txt", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", 1_000_000, True),
    ("adrules.txt", "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt", 1_000_000, True),
    ("urlhaus.txt", "https://urlhaus.abuse.ch/downloads/text/", 500_000, True),
    ("hagezi-fake.txt", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt", 100_000, True),
]

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

ADS_CATS = {"category-ads-all"}
CN_CATS = {"cn"}
PROXY_CATS = {c for c in GEOSITE_MAP if c not in ADS_CATS | CN_CATS}

# 核心域名保护名单:这些域名若出现在 REJECT 类列表中,视为上游异常(投毒/误杀)
PROTECTED_DOMAINS = {
    "google.com", "youtube.com", "gmail.com", "github.com", "microsoft.com", "apple.com",
    "amazon.com", "netflix.com", "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com", "telegram.org", "t.me", "discord.com", "reddit.com",
    "linkedin.com", "cloudflare.com", "baidu.com", "qq.com", "weixin.qq.com",
    "taobao.com", "tmall.com", "jd.com", "bilibili.com", "zhihu.com", "weibo.com",
    "163.com", "126.com", "douyin.com", "deepseek.com", "kimi.com", "openai.com",
    "anthropic.com", "claude.ai", "openrouter.ai", "huggingface.co", "sina.com.cn",
    "sohu.com", "youku.com", "iqiyi.com", "alipay.com", "paypal.com", "steampowered.com",
}

# 文件托管/CDN 平台:URL 级恶意链接常见于这些平台,但平台域名本身不可屏蔽
HOSTING_DOMAINS = {
    "github.com", "raw.githubusercontent.com", "githubusercontent.com", "github.io",
    "googleusercontent.com", "cloudfront.net", "azureedge.net", "cloudflare.net",
    "s3.amazonaws.com", "dropbox.com", "dropboxusercontent.com", "mega.nz",
    "mega.co.nz", "mediafire.com", "box.com", "onedrive.com", "amazonaws.com",
    "firebaseapp.com", "vercel.app", "netlify.app", "pages.dev", "gitlab.com",
}


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


# ---------- geosite 条目 -> 规则 ----------

def geosite_to_rule(typ, val):
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


# ---------- 社区列表解析 ----------

def parse_adblock_domains(path):
    """解析 adblock 格式(||domain^),返回纯域名集合"""
    out = set()
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if line.startswith("||") and line.endswith("^"):
            d = line[2:-1]
            if "*" in d or "/" in d or d.startswith(".") or not d:
                continue
            out.add(d)
    return out


def parse_plain_domains(path):
    """解析纯域名列表(每行一个域名,忽略 # 注释)"""
    out = set()
    for line in open(path, encoding="utf-8", errors="replace"):
        d = line.strip().lower()
        if not d or d.startswith("#"):
            continue
        if not all(c.isalnum() or c in ".-" for c in d):
            continue
        out.add(d)
    return out


def parse_urlhaus_hosts(path):
    """从 URLhaus URL 列表提取 host。
    过滤文件托管/CDN 平台:URL 级恶意链接不构成域名级恶意,
    否则屏蔽 github.com 等平台会误杀整个站点。"""
    out = set()
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url = line.split(" ")[0]
        host = url.split("/")[2] if "://" in url else url
        if not host or "." not in host:
            continue
        host = host.lower()
        # 平台域名本身不屏蔽(其父域命中同样跳过)
        cur = host
        skip = False
        while "." in cur:
            if cur in HOSTING_DOMAINS or cur in PROTECTED_DOMAINS:
                skip = True
                break
            cur = cur.split(".", 1)[1]
        if skip:
            continue
        out.add(host)
    return out


def dedupe_by_parent(domains):
    """父域已在集合中的子域去掉"""
    s = set(domains)
    return {d for d in s if "." not in d or d.split(".", 1)[1] not in s}


# ---------- 防投毒检查 ----------

def check_protected_conflicts(domains, label):
    """检查 REJECT 列表中是否出现保护域名本身或其父域"""
    conflicts = []
    for d in PROTECTED_DOMAINS:
        cur = d
        while "." in cur:
            if cur in domains:
                conflicts.append((d, cur))
                break
            cur = cur.split(".", 1)[1]
    if conflicts:
        print(f"  [安全拦截] {label} 包含受保护域名,疑似上游异常,已中止生成:")
        for full, hit in conflicts[:20]:
            print(f"    保护: {full}  <- 命中: {hit}")
        return False
    return True


def download_source(name, url, dest, min_bytes):
    if os.path.exists(dest):
        size = os.path.getsize(dest)
        if size >= min_bytes:
            print(f"  复用 {name} ({size // 1024} KB)")
            return
        print(f"  [警告] 本地 {name} 过小({size} B),重新下载")
    print(f"  下载 {name}")
    urllib.request.urlretrieve(url, dest)
    size = os.path.getsize(dest)
    if size < min_bytes:
        raise SystemExit(f"!! {name} 下载后仅 {size} B,低于下限 {min_bytes},视为异常终止")


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


def patch_clash_rule_sets(repo_root):
    """注入 REJECT 规则集引用(ads-extra / malware)到两个 Clash 文件。幂等。"""
    sets = [
        ("ads-extra", f"{RULES_URL}/ads-extra.list"),
        ("malware", f"{RULES_URL}/malware.list"),
    ]
    anchor = "GEOSITE,category-ads-all,REJECT"

    def hit(line):
        return anchor in line

    # rule-provider.yaml
    path = os.path.join(repo_root, "clash", "rule-provider.yaml")
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    missing = [n for n, _ in sets if not any(f"RULE-SET,{n},REJECT" in l for l in lines)]
    if missing:
        out = []
        for line in lines:
            out.append(line)
            if hit(line):
                for name, _ in sets:
                    out.append(f"- RULE-SET,{name},REJECT")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        print(f"  {path}: 注入 {missing}")
    else:
        print(f"  {path}: 规则集引用已存在")

    # clash-verge-merge.yaml
    path = os.path.join(repo_root, "clash", "clash-verge-merge.yaml")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if all(f"RULE-SET,{n},REJECT" in text for n, _ in sets) and "rule-providers:" in text:
        print(f"  {path}: 规则集引用已存在")
        return
    provider_block = "rule-providers:\n"
    for name, url in sets:
        provider_block += f"""  {name}:
    type: http
    behavior: classical
    url: {url}
    path: ./rules/{name}.yaml
    interval: 86400
"""
    lines = text.split("\n")
    # 清理已有注入
    out, in_prov = [], False
    for line in lines:
        if line.strip() == "rule-providers:":
            in_prov = True
            continue
        if in_prov:
            if line.strip() == "prepend-rules:":
                in_prov = False
            else:
                continue
        if any(f"RULE-SET,{n},REJECT" in line for n, _ in sets):
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
            for name, _ in sets:
                final.append(f"  - - RULE-SET,{name},REJECT")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(final) + "\n")
    print(f"  {path}: 注入 {[n for n, _ in sets]}")


# ---------- 主流程 ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="不下载数据源,复用本地文件")
    ap.add_argument("--dat-dir", default=".", help="数据源文件所在目录")
    args = ap.parse_args()

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dat_dir = os.path.abspath(args.dat_dir)

    print("== 1/8 准备数据源 ==")
    paths = {}
    if not args.offline:
        for name, url, min_bytes, _ in SOURCES:
            download_source(name, url, os.path.join(dat_dir, name), min_bytes)
    for name, _, min_bytes, _ in SOURCES:
        p = os.path.join(dat_dir, name)
        if os.path.getsize(p) < min_bytes:
            raise SystemExit(f"!! {name} 大小异常({os.path.getsize(p)} B),终止")
        paths[name] = p
    print(f"  共 {len(SOURCES)} 个数据源就绪")

    print("== 2/8 解析 geosite.dat ==")
    cats = load_geosite_cats(paths["geosite.dat"])
    print(f"  共 {len(cats)} 个分类")

    print("== 3/8 生成 geosite 规则集 ==")
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

    print("== 4/8 生成 ipcn.list(geoip.dat CN) ==")
    ipcn = set()
    for ipb, prefix in load_geoip_cn(paths["geoip.dat"]):
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

    print("== 5/8 生成 ads-extra.list(多源交叉验证) ==")
    antiad = parse_plain_domains(paths["anti-ad-domains.txt"])
    adguard = parse_adblock_domains(paths["adguard-filter.txt"])
    adrules = parse_adblock_domains(paths["adrules.txt"])
    print(f"  anti-AD : {len(antiad):>7}")
    print(f"  AdGuard : {len(adguard):>7}")
    print(f"  乘风    : {len(adrules):>7}")
    # 至少两源共现:单源独有条目不采用(交叉验证,降低单源异常影响)
    ads_extra = (antiad & adguard) | (antiad & adrules) | (adguard & adrules)
    ads_extra = dedupe_by_parent(ads_extra)
    print(f"  多源共现去重: {len(ads_extra):>7} 条")
    if not check_protected_conflicts(ads_extra, "ads-extra.list"):
        sys.exit(1)
    rules_dir = os.path.join(repo_root, "rules")
    os.makedirs(rules_dir, exist_ok=True)
    with open(os.path.join(rules_dir, "ads-extra.list"), "w") as f:
        f.write("# 广告域名补充(多源交叉验证,自动更新)\n")
        f.write("\n".join(f"DOMAIN-SUFFIX,{d}" for d in sorted(ads_extra)) + "\n")

    print("== 6/8 生成 malware.list(恶意/诈骗/钓鱼) ==")
    urlhaus = parse_urlhaus_hosts(paths["urlhaus.txt"])
    fake = parse_adblock_domains(paths["hagezi-fake.txt"])
    print(f"  URLhaus: {len(urlhaus):>7}")
    print(f"  hagezi : {len(fake):>7}")
    malware = dedupe_by_parent(urlhaus | fake)
    print(f"  合并去重: {len(malware):>7} 条")
    if not check_protected_conflicts(malware, "malware.list"):
        sys.exit(1)
    with open(os.path.join(rules_dir, "malware.list"), "w") as f:
        f.write("# 恶意/诈骗/钓鱼域名(自动更新)\n")
        f.write("\n".join(f"DOMAIN-SUFFIX,{d}" for d in sorted(malware)) + "\n")

    print("== 7/8 同步 Clash 文件 ==")
    patch_clash_platform_extra(repo_root, cats)
    patch_clash_rule_sets(repo_root)

    print("== 8/8 生成 shadowrocket.conf ==")
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
    malware_emitted = False
    for idx, parts in enumerate(rules):
        kind = parts[0]
        if kind == "GEOSITE":
            name = parts[1]
            if name in ADS_CATS:
                conf_lines.append(f"RULE-SET,{BASE_URL}/ads.list,REJECT")
                if not ads_extra_emitted:
                    conf_lines.append(f"RULE-SET,{RULES_URL}/ads-extra.list,REJECT")
                    ads_extra_emitted = True
                if not malware_emitted:
                    conf_lines.append(f"RULE-SET,{RULES_URL}/malware.list,REJECT")
                    malware_emitted = True
            elif name in CN_CATS:
                conf_lines.append(f"RULE-SET,{BASE_URL}/cn.list,DIRECT")
            elif name in PROXY_CATS:
                if idx == last_proxy_geosite:
                    conf_lines.append(f"RULE-SET,{BASE_URL}/proxy.list,Proxy")
            else:
                print(f"  [警告] 未映射的 GEOSITE 分类: {name},已跳过")
            continue
        if kind == "RULE-SET":
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
              os.path.join(rules_dir, "ads-extra.list"), os.path.join(rules_dir, "malware.list")):
        print(f"  {os.path.relpath(p, repo_root)}  ({os.path.getsize(p) // 1024} KB)")


if __name__ == "__main__":
    main()
