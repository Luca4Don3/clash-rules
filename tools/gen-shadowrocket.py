#!/usr/bin/env python3
"""从统一政策源与上游数据库生成 Clash / Shadowrocket 产物。"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

REPO = "Luca4Don3/clash-rules"
BRANCH = "master"
RAW = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}"
DAT_RELEASES = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest"
ALLOWED_POLICIES = {"REJECT", "DIRECT", "SENSITIVE", "DIRECT-PREFERRED", "PROXY"}
POLICY_ORDER = {"REJECT": 0, "PRIVATE": 1, "SENSITIVE": 2, "DIRECT": 3,
                "DIRECT-PREFERRED": 4, "PROXY": 5}
PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"), ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"), ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"), ipaddress.ip_network("ff00::/8"),
)
FORCE_DIRECT_DOMAINS = {
    "volcengine.com", "volcengine.net", "volcengineapi.com", "volcengine-api.com",
    "volces.com", "volceapi.com", "volccdn.com", "volcdns.com", "volcvideo.com",
    "volcimagex.com", "byteimg.com", "ibytedtos.com",
}
SOURCES = [
    ("geosite.dat", f"{DAT_RELEASES}/geosite.dat", 1_000_000),
    ("geoip.dat", f"{DAT_RELEASES}/geoip.dat", 5_000_000),
    ("anti-ad-domains.txt", "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt", 1_000_000),
    ("adguard-filter.txt", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", 1_000_000),
    ("adrules.txt", "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt", 1_000_000),
    ("urlhaus.txt", "https://urlhaus.abuse.ch/downloads/text/", 500_000),
]
TYPE_PLAIN, TYPE_REGEX, TYPE_DOMAIN, TYPE_FULL = 0, 1, 2, 3
PROTECTED_DOMAINS = {
    "google.com", "youtube.com", "github.com", "microsoft.com", "apple.com",
    "amazon.com", "netflix.com", "facebook.com", "openai.com", "baidu.com",
    "qq.com", "taobao.com", "jd.com", "bilibili.com", "deepseek.com",
}
HOSTING_DOMAINS = {
    "github.com", "githubusercontent.com", "github.io", "googleusercontent.com",
    "cloudfront.net", "azureedge.net", "s3.amazonaws.com", "amazonaws.com",
    "vercel.app", "netlify.app", "pages.dev", "gitlab.com",
}


def atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content.rstrip() + "\n", encoding="utf-8")
    os.replace(tmp, path)


def parse_varint(buf, offset):
    value = shift = 0
    for _ in range(10):
        if offset >= len(buf):
            raise ValueError("truncated protobuf varint")
        byte = buf[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    raise ValueError("protobuf varint is too long")


def skip_field(buf, offset, wire):
    if wire == 0:
        return parse_varint(buf, offset)[1]
    if wire == 1:
        end = offset + 8
    elif wire == 2:
        size, offset = parse_varint(buf, offset)
        end = offset + size
    elif wire == 5:
        end = offset + 4
    else:
        raise ValueError(f"unsupported protobuf wire type: {wire}")
    if end > len(buf):
        raise ValueError("truncated protobuf field")
    return end


def fields(buf):
    offset = 0
    while offset < len(buf):
        tag, offset = parse_varint(buf, offset)
        number, wire = tag >> 3, tag & 7
        if number == 0:
            raise ValueError("invalid protobuf field number 0")
        if wire == 2:
            size, start = parse_varint(buf, offset)
            end = start + size
            if end > len(buf):
                raise ValueError("truncated protobuf field")
            yield number, wire, buf[start:end]
            offset = end
        elif wire == 0:
            value, offset = parse_varint(buf, offset)
            yield number, wire, value
        else:
            offset = skip_field(buf, offset, wire)


def parse_domain(buf):
    typ, value = TYPE_PLAIN, ""
    for number, wire, item in fields(buf):
        if number == 1 and wire == 0:
            typ = item
        elif number == 2 and wire == 2:
            value = item.decode("utf-8", "replace")
    return typ, value


def parse_cidr(buf):
    raw, prefix = b"", 0
    for number, wire, item in fields(buf):
        if number == 1 and wire == 2:
            raw = item
        elif number == 2 and wire == 0:
            prefix = item
    return raw, prefix


def load_geosite(path):
    result = {}
    for number, wire, record in fields(Path(path).read_bytes()):
        if number != 1 or wire != 2:
            continue
        code, domains = None, []
        for field, kind, value in fields(record):
            if field == 1 and kind == 2:
                code = value.decode("utf-8", "replace").upper()
            elif field == 2 and kind == 2:
                domains.append(parse_domain(value))
        if code:
            result[code] = domains
    return result


def load_geoip_cn(path):
    result = []
    for number, wire, record in fields(Path(path).read_bytes()):
        if number != 1 or wire != 2:
            continue
        code, cidrs = None, []
        for field, kind, value in fields(record):
            if field == 1 and kind == 2:
                code = value.decode("utf-8", "replace").upper()
            elif field == 2 and kind == 2:
                cidrs.append(parse_cidr(value))
        if code == "CN":
            result.extend(cidrs)
    return result


def geosite_rule(typ, value):
    value = value.split("@", 1)[0].strip().lstrip(".")
    if not value:
        return None
    if typ == TYPE_PLAIN:
        return f"DOMAIN-KEYWORD,{value}"
    if typ == TYPE_DOMAIN:
        return f"DOMAIN-SUFFIX,{value}"
    if typ == TYPE_FULL:
        return f"DOMAIN,{value}"
    # Shadowrocket 的 URL-REGEX 匹配 URL，不等价于 geosite 域名正则。
    return None


def ancestors(domain):
    parts = domain.split(".")
    return (".".join(parts[i:]) for i in range(1, len(parts)))


def dedupe_by_ancestor(domains):
    source = set(domains)
    return {domain for domain in source if not any(parent in source for parent in ancestors(domain))}


def is_protected(domain):
    return domain in PROTECTED_DOMAINS or any(parent in PROTECTED_DOMAINS for parent in ancestors(domain))


def is_hosting(domain):
    return domain in HOSTING_DOMAINS or any(parent in HOSTING_DOMAINS for parent in ancestors(domain))


def is_private_ip(ip):
    return any(ip.version == network.version and ip in network for network in PRIVATE_NETWORKS)


def protected_conflicts(domains):
    source = set(domains)
    return sorted({candidate for protected in PROTECTED_DOMAINS
                   for candidate in (protected, *ancestors(protected)) if candidate in source})


def parse_urlhaus_hosts(path):
    domains, networks = set(), set()
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        value = raw.strip().split(maxsplit=1)[0] if raw.strip() else ""
        if not value or value.startswith("#"):
            continue
        try:
            hostname = urlsplit(value if "://" in value else "//" + value).hostname
        except ValueError:
            continue
        if not hostname:
            continue
        hostname = hostname.rstrip(".").lower()
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            if re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", hostname) and not is_protected(hostname) and not is_hosting(hostname):
                domains.add(hostname)
            continue
        if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified) and not is_private_ip(ip):
            networks.add(f"{'IP-CIDR' if ip.version == 4 else 'IP-CIDR6'},{ip}/{ip.max_prefixlen},no-resolve")
    # URLhaus 是逐 URL IOC：保留精确主机，不能提升到父域（如 mediafire.com）。
    return domains, networks


def parse_adblock(path):
    result = set()
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip().lower()
        if line.startswith("||") and line.endswith("^"):
            domain = line[2:-1]
            if re.fullmatch(r"[a-z0-9.-]+", domain):
                result.add(domain)
    return result


def parse_plain(path):
    return {line.strip().lower() for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
            if re.fullmatch(r"[a-z0-9.-]+", line.strip().lower())}


def parse_policy_source(path):
    rules = []
    for line_number, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(",")]
        policy_index = len(parts) - 2 if parts[-1] == "no-resolve" else len(parts) - 1
        policy = parts[policy_index]
        if policy not in ALLOWED_POLICIES:
            raise ValueError(f"{path}:{line_number}: invalid policy {policy!r}")
        body = parts[:policy_index] + parts[policy_index + 1:]
        if len(body) < 2:
            raise ValueError(f"{path}:{line_number}: malformed rule")
        group = policy
        if body[0].startswith("IP-CIDR"):
            try:
                network = ipaddress.ip_network(body[1], strict=False)
            except ValueError as error:
                raise ValueError(f"{path}:{line_number}: invalid network {body[1]!r}") from error
            if any(network.version == item.version and network.subnet_of(item) for item in PRIVATE_NETWORKS):
                if policy != "DIRECT":
                    raise ValueError(f"{path}:{line_number}: private networks must use DIRECT")
                group = "PRIVATE"
        rules.append((group, policy, ",".join(body)))
    if not rules:
        raise ValueError(f"{path}: zero rules")
    rules.sort(key=lambda item: POLICY_ORDER[item[0]])
    return rules


def attach_policy(rule, policy):
    if rule.endswith(",no-resolve"):
        return f"{rule[:-11]},{policy},no-resolve"
    return f"{rule},{policy}"


def write_client_outputs(root, rules):
    target = {"REJECT": "广告拦截", "DIRECT": "DIRECT", "SENSITIVE": "敏感服务",
              "DIRECT-PREFERRED": "直连优先", "PROXY": "日常代理"}
    providers = {name: [] for name in ("reject", "direct", "sensitive", "direct-preferred", "proxy")}
    names = {"REJECT": "reject", "DIRECT": "direct", "SENSITIVE": "sensitive",
             "DIRECT-PREFERRED": "direct-preferred", "PROXY": "proxy"}
    for group, policy, body in rules:
        if not body.startswith("GEOSITE,") and group != "PRIVATE":
            providers[names[policy]].append(body)
    for supplemental in (root / "rules" / "ads-extra.list", root / "rules" / "malware.list"):
        if supplemental.exists():
            providers["reject"].extend(line.strip() for line in supplemental.read_text(encoding="utf-8").splitlines()
                                       if line.strip() and not line.startswith("#"))
    for name, entries in providers.items():
        atomic_write(root / "rules" / f"{name}.list", "# 自动生成；不含策略目标\n" + "\n".join(dict.fromkeys(entries)))

    payload = [body for _, policy, body in rules if policy == "PROXY"]
    atomic_write(root / "clash" / "rule-provider.yaml", "# 通用代理规则 provider\npayload:\n" +
                 "\n".join(f"  - {json.dumps(rule, ensure_ascii=False)}" for rule in payload))

    provider_block = []
    for name in providers:
        provider_block.extend([
            f"  {name}:", "    type: http", "    behavior: classical", "    format: text",
            f"    url: {RAW}/rules/{name}.list", f"    path: ./rules/{name}.list", "    interval: 86400",
        ])
    private = [body for group, _, body in rules if group == "PRIVATE"]
    geosite = {policy: [body for _, item_policy, body in rules
                        if item_policy == policy and body.startswith("GEOSITE,")]
               for policy in ALLOWED_POLICIES}
    force_direct = [f"DOMAIN-SUFFIX,{domain}" for domain in sorted(FORCE_DIRECT_DOMAINS)]
    legacy = [
        "# Legacy：仅兼容机场已有 PROXY 组；推荐使用 clash-verge-script.js",
        "profile:", "  store-selected: true", "rule-providers:", *provider_block, "rules:",
        *[f"  - {attach_policy(rule, 'DIRECT')}" for rule in force_direct],
        "  - RULE-SET,reject,REJECT", *[f"  - {attach_policy(rule, 'REJECT')}" for rule in geosite["REJECT"]],
        *[f"  - {attach_policy(rule, 'DIRECT')}" for rule in private],
        "  - RULE-SET,sensitive,PROXY", *[f"  - {attach_policy(rule, 'PROXY')}" for rule in geosite["SENSITIVE"]],
        "  - RULE-SET,direct,DIRECT", *[f"  - {attach_policy(rule, 'DIRECT')}" for rule in geosite["DIRECT"]],
        "  - RULE-SET,direct-preferred,DIRECT",
        *[f"  - {attach_policy(rule, 'DIRECT')}" for rule in geosite["DIRECT-PREFERRED"]],
        "  - RULE-SET,proxy,PROXY", *[f"  - {attach_policy(rule, 'PROXY')}" for rule in geosite["PROXY"]],
    ]
    legacy.extend([
        "  - GEOIP,CN,DIRECT,no-resolve", "  - MATCH,DIRECT",
    ])
    atomic_write(root / "clash" / "clash-verge-merge.yaml", "\n".join(legacy))

    sr = [
        "# Shadowrocket 完整配置；策略组通过订阅节点正则自动装载",
        "[General]", "dns-server = https://doh.pub/dns-query,https://dns.alidns.com/dns-query",
        "fallback-dns-server = 223.5.5.5,119.29.29.29", "ipv6 = true", "",
        "[Proxy Group]",
        "日常代理 = url-test,policy-regex-filter=^(?!.*(?:流量|到期|剩余|官网|套餐)).+$,url=http://www.gstatic.com/generate_204,interval=300,tolerance=50",
        "敏感服务 = select,policy-regex-filter=^(?!.*(?:流量|到期|剩余|官网|套餐)).+$",
        "直连优先 = select,DIRECT,日常代理", "广告拦截 = select,REJECT,DIRECT", "", "[Rule]",
        *[attach_policy(rule, "DIRECT") for rule in force_direct],
        f"RULE-SET,{RAW}/rules/reject.list,广告拦截",
        f"RULE-SET,{RAW}/shadowrocket/geosite/ads.list,广告拦截",
        *[attach_policy(rule, "DIRECT") for rule in private],
        f"RULE-SET,{RAW}/rules/sensitive.list,敏感服务",
        f"RULE-SET,{RAW}/shadowrocket/geosite/sensitive.list,敏感服务",
        f"RULE-SET,{RAW}/rules/direct.list,DIRECT",
        f"RULE-SET,{RAW}/shadowrocket/geosite/cn.list,DIRECT",
        f"RULE-SET,{RAW}/rules/direct-preferred.list,直连优先",
        *([f"RULE-SET,{RAW}/shadowrocket/geosite/direct-preferred.list,直连优先"]
          if geosite["DIRECT-PREFERRED"] else []),
        f"RULE-SET,{RAW}/rules/proxy.list,日常代理",
        f"RULE-SET,{RAW}/shadowrocket/geosite/proxy.list,日常代理",
    ]
    sr.extend([
        "# 固定源快照；下面的客户端 GeoIP 作为回退",
        f"RULE-SET,{RAW}/shadowrocket/geosite/ipcn.list,DIRECT",
        "GEOIP,CN,DIRECT", "FINAL,DIRECT",
    ])
    atomic_write(root / "shadowrocket" / "shadowrocket.conf", "\n".join(sr))


def download_sources(dat_dir):
    manifest = {"generated_at": "CI", "sources": []}
    dat_dir.mkdir(parents=True, exist_ok=True)
    for name, url, minimum in SOURCES:
        dest = dat_dir / name
        subprocess.run(["curl", "--fail", "--location", "--retry", "5", "--retry-all-errors",
                        "--retry-delay", "5", "--connect-timeout", "30", "--max-time", "600",
                        "--http1.1", "--output", str(dest), url], check=True)
        if dest.stat().st_size < minimum:
            raise RuntimeError(f"{name}: {dest.stat().st_size} bytes, minimum is {minimum}")
        manifest["sources"].append({"name": name, "url": url, "version": "latest",
                                    "sha256": hashlib.sha256(dest.read_bytes()).hexdigest()})
    return manifest


def generate_upstream(root, dat_dir, rules):
    cats = load_geosite(dat_dir / "geosite.dat")
    output_by_policy = {"REJECT": "ads", "DIRECT": "cn", "SENSITIVE": "sensitive",
                       "DIRECT-PREFERRED": "direct-preferred", "PROXY": "proxy"}
    categories = {output: [] for output in output_by_policy.values()}
    for _, policy, body in rules:
        if not body.startswith("GEOSITE,"):
            continue
        category = body.split(",", 1)[1].strip()
        output = output_by_policy.get(policy)
        if output and category and category not in categories[output]:
            categories[output].append(category)
    required_outputs = {"ads", "cn", "sensitive", "proxy"}
    missing = [output for output in required_outputs if not categories[output]]
    if missing:
        raise RuntimeError(f"policy source has no GEOSITE categories for: {', '.join(sorted(missing))}")
    all_skipped = set()
    for output, wanted in categories.items():
        if not wanted:
            continue
        result, skipped_patterns = set(), set()
        for category in wanted:
            # load_geosite normalizes category codes to upper case; policy source remains lower case.
            for typ, value in cats.get(category.upper(), []):
                rule = geosite_rule(typ, value)
                if rule:
                    result.add(rule)
                elif typ == TYPE_REGEX:
                    skipped_patterns.add(value)
        all_skipped.update(skipped_patterns)
        source_categories = ",".join(wanted)
        atomic_write(root / "shadowrocket" / "geosite" / f"{output}.list",
                     f"# 自动生成；源分类 {source_categories}；跳过无法可靠转换的域名正则 {len(skipped_patterns)} 条\n"
                     + "\n".join(sorted(result)))
        print(f"{output}.list: {len(result)} rules, skipped regex: {len(skipped_patterns)}")
    ip_rules = set()
    for packed, prefix in load_geoip_cn(dat_dir / "geoip.dat"):
        try:
            ip = ipaddress.ip_address(packed)
            ip_rules.add(f"{'IP-CIDR' if ip.version == 4 else 'IP-CIDR6'},{ip}/{prefix},no-resolve")
        except ValueError:
            continue
    atomic_write(root / "shadowrocket" / "geosite" / "ipcn.list", "# 自动生成\n" + "\n".join(sorted(ip_rules)))
    ads = dedupe_by_ancestor((parse_plain(dat_dir / "anti-ad-domains.txt") & parse_adblock(dat_dir / "adguard-filter.txt")) |
                             (parse_plain(dat_dir / "anti-ad-domains.txt") & parse_adblock(dat_dir / "adrules.txt")) |
                             (parse_adblock(dat_dir / "adguard-filter.txt") & parse_adblock(dat_dir / "adrules.txt")))
    malware_domains, malware_ips = parse_urlhaus_hosts(dat_dir / "urlhaus.txt")
    for label, domains in (("ads-extra", ads), ("malware", malware_domains)):
        conflict = protected_conflicts(domains)
        if conflict:
            raise RuntimeError(f"{label}: protected domain conflict: {conflict[:5]}")
    atomic_write(root / "rules" / "ads-extra.list", "# 自动生成\n" + "\n".join(f"DOMAIN-SUFFIX,{d}" for d in sorted(ads)))
    malware = [f"DOMAIN,{d}" for d in sorted(malware_domains)] + sorted(malware_ips)
    atomic_write(root / "rules" / "malware.list", "# 自动生成\n" + "\n".join(malware))
    return len(all_skipped)


def source_snapshot_id(sources):
    material = "\n".join(f"{item['name']}:{item['sha256']}" for item in sources)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--clients-only", action="store_true")
    parser.add_argument("--dat-dir", default=".temp/upstream")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    rules = parse_policy_source(root / "rules" / "policy.list")
    if args.clients_only:
        write_client_outputs(root, rules)
        print("client outputs generated")
        return
    dat_dir = Path(args.dat_dir).resolve()
    if args.offline:
        manifest = {"generated_at": "offline", "sources": []}
        for name, url, minimum in SOURCES:
            path = dat_dir / name
            if not path.exists() or path.stat().st_size < minimum:
                raise RuntimeError(f"missing or undersized offline source: {path}")
            manifest["sources"].append({"name": name, "url": url, "version": "latest",
                                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    else:
        manifest = download_sources(dat_dir)
    manifest["snapshot_sha256"] = source_snapshot_id(manifest["sources"])
    skipped = generate_upstream(root, dat_dir, rules)
    write_client_outputs(root, rules)
    print(f"client outputs generated; skipped geosite regex: {skipped}")
    atomic_write(root / "rules" / "sources.json", json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
