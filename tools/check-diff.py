#!/usr/bin/env python3
"""生成产物的结构、安全与异常差异门禁。"""

import argparse
import hashlib
import ipaddress
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GENERATED = [
    "clash/clash-verge-merge.yaml", "clash/rule-provider.yaml",
    "shadowrocket/shadowrocket.conf", "shadowrocket/geosite/ads.list",
    "shadowrocket/geosite/cn.list", "shadowrocket/geosite/sensitive.list", "shadowrocket/geosite/proxy.list",
    "shadowrocket/geosite/ipcn.list", "rules/ads-extra.list", "rules/malware.list",
    "rules/reject.list", "rules/direct.list", "rules/sensitive.list",
    "rules/direct-preferred.list", "rules/proxy.list", "rules/sources.json",
]
VALID_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6",
               "GEOSITE", "GEOIP", "RULE-SET", "MATCH", "FINAL"}
GEOSITE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6"}
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "100.64.0.0/10", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
))


def git_head(path):
    result = subprocess.run(["git", "show", f"HEAD:{path}"], cwd=ROOT, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else None


def rule_lines(path):
    return [line.strip().removeprefix("- ").strip('"') for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith(("#", "payload:", "["))]


def validate():
    issues = []
    manifest_path = ROOT / "rules/sources.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        snapshot = manifest.get("snapshot_sha256", "")
        sources = manifest.get("sources") or []
        if len(snapshot) != 64 or any(char not in "0123456789abcdef" for char in snapshot):
            issues.append("rules/sources.json: missing or invalid snapshot_sha256")
        if not sources:
            issues.append("rules/sources.json: no source entries")
        else:
            material = "\n".join(f"{item['name']}:{item['sha256']}" for item in sources)
            expected = hashlib.sha256(material.encode("utf-8")).hexdigest()
            if snapshot != expected:
                issues.append("rules/sources.json: snapshot_sha256 does not match source entries")
    except (OSError, ValueError, TypeError) as error:
        issues.append(f"rules/sources.json: invalid manifest ({error})")
    provider_domains = {}
    for name in ("reject", "direct", "sensitive", "direct-preferred", "proxy"):
        path = ROOT / "rules" / f"{name}.list"
        entries = rule_lines(path) if path.exists() else []
        if not entries:
            issues.append(f"{path.relative_to(ROOT)}: zero rules")
        if len(entries) != len(set(entries)):
            issues.append(f"{path.relative_to(ROOT)}: duplicate rules")
        provider_domains[name] = {
            entry.split(",", 1)[1] for entry in entries
            if entry.split(",", 1)[0] in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
            and "," in entry
        }
        for entry in entries:
            if entry.split(",", 1)[0] not in VALID_TYPES:
                issues.append(f"{path.relative_to(ROOT)}: invalid type: {entry}")
                break
    reject_domains = provider_domains.get("reject", set())
    for name in ("direct", "sensitive", "direct-preferred", "proxy"):
        overlap = sorted(reject_domains & provider_domains.get(name, set()))
        if overlap:
            issues.append(f"rules/{name}.list overlaps rules/reject.list: {overlap[:10]}")
    reject_entries = rule_lines(ROOT / "rules/reject.list") if (ROOT / "rules/reject.list").exists() else []
    private_conflicts = []
    for entry in reject_entries:
        parts = entry.split(",")
        if parts[0] not in ("IP-CIDR", "IP-CIDR6"):
            continue
        try:
            network = ipaddress.ip_network(parts[1], strict=False)
        except (IndexError, ValueError):
            issues.append(f"rules/reject.list: malformed network rule: {entry}")
            continue
        if len(parts) != 3 or parts[2] != "no-resolve":
            issues.append(f"rules/reject.list: IP rule must use no-resolve: {entry}")
        if any(network.version == private.version and network.overlaps(private) for private in PRIVATE_NETWORKS):
            private_conflicts.append(entry)
    if private_conflicts:
        issues.append(f"rules/reject.list: private network conflict: {private_conflicts[:5]}")
    geosite_names = ["ads", "cn", "sensitive", "proxy", "ipcn"]
    if (ROOT / "shadowrocket/geosite/direct-preferred.list").exists():
        geosite_names.append("direct-preferred")
    for name in geosite_names:
        path = ROOT / "shadowrocket/geosite" / f"{name}.list"
        entries = rule_lines(path) if path.exists() else []
        if not entries:
            issues.append(f"{path.relative_to(ROOT)}: zero rules")
            continue
        for entry in entries:
            parts = entry.split(",")
            if parts[0] not in GEOSITE_TYPES:
                issues.append(f"{path.relative_to(ROOT)}: invalid rule type: {entry}")
                break
            if parts[0] in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
                if len(parts) != 2 or not parts[1].strip():
                    issues.append(f"{path.relative_to(ROOT)}: malformed domain rule: {entry}")
                    break
            else:
                try:
                    ipaddress.ip_network(parts[1], strict=False)
                except (IndexError, ValueError):
                    issues.append(f"{path.relative_to(ROOT)}: malformed network rule: {entry}")
                    break
                if len(parts) != 3 or parts[2] != "no-resolve":
                    issues.append(f"{path.relative_to(ROOT)}: IP rule must use no-resolve: {entry}")
                    break

    script = (ROOT / "clash/clash-verge-script.js").read_text(encoding="utf-8")
    for required in ('"日常代理"', '"敏感服务"', '"直连优先"', '"广告拦截"', '"MATCH,DIRECT"'):
        if required not in script:
            issues.append(f"clash-verge-script.js: missing {required}")
    target_names = {"REJECT": "广告拦截", "DIRECT": "DIRECT", "SENSITIVE": "敏感服务",
                    "DIRECT-PREFERRED": "直连优先", "PROXY": "日常代理"}
    policy_path = ROOT / "rules/policy.list"
    for raw in policy_path.read_text(encoding="utf-8").splitlines():
        parts = [part.strip() for part in raw.split(",")]
        if len(parts) < 3 or parts[0] != "GEOSITE" or parts[-1] not in target_names:
            continue
        expected = f'"GEOSITE,{parts[1]},{target_names[parts[-1]]}"'
        if expected not in script:
            issues.append(f"clash-verge-script.js: missing {expected}")
    if script.index('"RULE-SET,sensitive,敏感服务"') > script.index('"GEOSITE,cn,DIRECT"'):
        issues.append("clash-verge-script.js: sensitive rules are shadowed by GEOSITE cn")
    for private_rule in (
        "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve", "IP-CIDR,240.0.0.0/4,DIRECT,no-resolve",
        "IP-CIDR6,ff00::/8,DIRECT,no-resolve",
    ):
        if f'"{private_rule}"' not in script:
            issues.append(f"clash-verge-script.js: missing {private_rule}")
    for category in ("google", "youtube", "telegram", "facebook", "twitter", "instagram",
                     "whatsapp", "discord", "reddit", "netflix", "spotify", "twitch"):
        if f'"GEOSITE,{category},日常代理"' not in script:
            issues.append(f"clash-verge-script.js: missing GEOSITE,{category}")

    shadow = (ROOT / "shadowrocket/shadowrocket.conf").read_text(encoding="utf-8")
    if not shadow.rstrip().endswith("FINAL,DIRECT"):
        issues.append("shadowrocket.conf: FINAL is not DIRECT")
    if "8.8.8.8" in shadow or "fallback," in shadow:
        issues.append("shadowrocket.conf: forbidden DNS or fallback group")
    if "policy-regex-filter=" not in shadow:
        issues.append("shadowrocket.conf: subscription nodes are not selected by regex")
    sensitive_at = shadow.find("/rules/sensitive.list,敏感服务")
    sensitive_geosite_at = shadow.find("/shadowrocket/geosite/sensitive.list,敏感服务")
    cn_at = shadow.find("/shadowrocket/geosite/cn.list,DIRECT")
    if sensitive_at < 0 or sensitive_geosite_at < 0 or cn_at < 0:
        issues.append("shadowrocket.conf: missing sensitive or CN rule provider")
    elif sensitive_at > cn_at or sensitive_geosite_at > cn_at:
        issues.append("shadowrocket.conf: sensitive rules are shadowed by CN rules")
    return issues


def diff_guard():
    issues = []
    for relative in GENERATED:
        path = ROOT / relative
        if not path.exists():
            if relative != "rules/sources.json":
                issues.append(f"{relative}: missing")
            continue
        old = git_head(relative)
        if old is None:
            continue
        new_count = len(rule_lines(path))
        old_count = len([line for line in old.splitlines() if line.strip() and not line.lstrip().startswith("#")])
        # 首次从旧版单文件迁移到统一政策源时允许预期的大幅缩减。
        legacy_client_migration = relative in {"clash/clash-verge-merge.yaml", "clash/rule-provider.yaml",
                                                "shadowrocket/shadowrocket.conf"} and "clash-verge-script.js" not in subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout
        # 旧远端 malware.list 来自已移除的多源生成器；本次迁移到 URLhaus 精确解析后
        # 只放行这一个文件的一次性缩减。提交后新文件头不再匹配，后续异常缩减仍会触发门禁。
        legacy_malware_migration = (relative == "rules/malware.list"
                                     and old.splitlines()
                                     and old.splitlines()[0].startswith("# 恶意/诈骗/钓鱼域名"))
        # geolocation-!cn 末端兜底会一次性扩大 Shadowrocket proxy 列表；新文件头会记录源分类，
        # 提交后该条件自动失效，后续异常膨胀仍会触发门禁。
        legacy_geolocation_migration = (relative == "shadowrocket/geosite/proxy.list"
                                       and "源分类 geolocation-!cn" not in old)
        migration = legacy_client_migration or legacy_malware_migration or legacy_geolocation_migration
        if old_count and not migration:
            if new_count == 0:
                issues.append(f"{relative}: became empty")
            elif new_count < old_count * 0.5:
                issues.append(f"{relative}: decreased {old_count - new_count} lines (>50%)")
            elif new_count > old_count + max(5000, int(old_count * 0.5)):
                issues.append(f"{relative}: increased {new_count - old_count} lines abnormally")
    return issues


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--structural-only", action="store_true")
    args = parser.parse_args()
    issues = validate()
    if not args.structural_only:
        issues.extend(diff_guard())
    if issues:
        print("[异常] 生成门禁失败:")
        for issue in issues:
            print(f"  - {issue}")
        return 1
    print("生成门禁通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
