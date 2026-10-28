import hashlib
import importlib.util
import ipaddress
import re
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("generator", ROOT / "tools/gen-shadowrocket.py")
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


def varint(value):
    output = bytearray()
    while value > 0x7f:
        output.append((value & 0x7f) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def bytes_field(number, payload):
    return varint((number << 3) | 2) + varint(len(payload)) + payload


def varint_field(number, value):
    return varint(number << 3) + varint(value)


def geosite_fixture(path, categories):
    records = []
    for category, domains in categories.items():
        record = bytes_field(1, category.encode("ascii"))
        for domain in domains:
            record += bytes_field(2, varint_field(1, GEN.TYPE_DOMAIN) + bytes_field(2, domain.encode("ascii")))
        records.append(bytes_field(1, record))
    path.write_bytes(b"".join(records))


def geoip_cn_fixture(path):
    cidr = bytes_field(1, ipaddress.ip_address("1.2.3.0").packed) + varint_field(2, 24)
    record = bytes_field(1, b"CN") + bytes_field(2, cidr)
    path.write_bytes(bytes_field(1, record))


APPLE_RELAY_HOSTS = (
    "apple-relay.apple.com", "apple-relay.cloudflare.com", "apple-relay.fastly-edge.com", "cp4.cloudflare.com",
)
APPLE_CN_HOSTS = (
    "apps.apple.com", "buy.apps.apple.com", "itunes.apple.com", "p42-buy.itunes.apple.com",
    "itunes.com", "mzstatic.com", "is1-ssl.mzstatic.com", "amp-api.media.apple.com",
    "music.apple.com", "amp-api.music.apple.com", "weather-data.apple.com",
    "weather-map.apple.com", "weather-map2.apple.com", "weatherkit.apple.com",
    "apple.com.cn", "www.apple.com.cn", "icloud.com.cn", "www.icloud.com.cn", "apzones.com",
    "push.apple.com", "courier.push.apple.com", "updates.cdn-apple.com",
    "updates-http.cdn-apple.com", "mesu.apple.com", "gdmf.apple.com",
    "idmsa.apple.com", "appleid.apple.com", "gsa.apple.com", "appleid.cdn-apple.com",
    "configuration.ls.apple.com", "account.apple.com", "configuration.apple.com",
    "gg.apple.com", "gs.apple.com", "swdist.apple.com",
)
APPLE_PROXY_HOSTS = (
    *APPLE_RELAY_HOSTS, "tv.apple.com", "tv.applemusic.com", "apple.news", "news.apple.com", "news-client.apple.com",
    "news-assets.apple.com", "news-edge.apple.com", "news-events.apple.com",
    "testflight.apple.com", "uts-api.itunes.apple.com", "hls.itunes.apple.com",
    "hls-amt.itunes.apple.com", "hls-svod.itunes.apple.com", "np-edge.itunes.apple.com",
    "play-edge.itunes.apple.com", "gspe1-ssl.ls.apple.com", "mask.icloud.com",
    "mask-api.icloud.com", "mask-h2.icloud.com", "cvws.icloud-content.com",
)


def domain_matches(kind, value, host):
    """仅模拟域名规则，严格检查后缀边界；不解析 DNS，也不匹配 IP/GeoIP。"""
    value, host = value.lower(), host.lower()
    if kind == "DOMAIN":
        return host == value
    if kind == "DOMAIN-SUFFIX":
        return host == value or host.endswith("." + value)
    if kind == "DOMAIN-KEYWORD":
        return value in host
    return False


def shadowrocket_domain_rules(root, config):
    """展开真实配置的本地 RULE-SET；禁止网络访问并保留首条命中来源。"""
    entries, defaults, section = [], {}, ""
    for raw in config.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line
            continue
        if section == "[Proxy Group]" and "=" in line:
            name, definition = line.split("=", 1)
            parts = [part.strip() for part in definition.split(",")]
            if len(parts) > 1 and parts[0] == "select" and parts[1] in {"REJECT", "DIRECT"}:
                defaults[name.strip()] = parts[1]
        if section != "[Rule]":
            continue
        parts = [part.strip() for part in line.split(",")]
        if parts[0] == "RULE-SET":
            prefix = GEN.RAW + "/"
            if not parts[1].startswith(prefix):
                raise AssertionError(f"non-local rule provider: {parts[1]}")
            relative = parts[1][len(prefix):]
            path = (root / relative).resolve()
            if not path.is_relative_to(root.resolve()):
                raise AssertionError(f"rule provider outside repository: {relative}")
            for body in path.read_text(encoding="utf-8").splitlines():
                rule = [part.strip() for part in body.strip().split(",")]
                if rule[0] in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
                    entries.append((rule[0], rule[1], defaults.get(parts[2], parts[2]), relative))
        elif parts[0] == "FINAL":
            entries.append(("FINAL", "", defaults.get(parts[1], parts[1]), "FINAL"))
        elif parts[0] in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
            entries.append((parts[0], parts[1], defaults.get(parts[2], parts[2]), "inline"))
    return entries


def first_domain_route(entries, host):
    for kind, value, target, origin in entries:
        if kind == "FINAL" or domain_matches(kind, value, host):
            return target, origin
    raise AssertionError(f"no domain route or FINAL for {host}")


class GeneratorTests(unittest.TestCase):
    def test_urlhaus_strips_auth_ports_brackets_and_filters_special_ips(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "urlhaus.txt"
            source.write_text(
                "http://user:pass@evil.example:8080/a\n"
                "http://8.8.4.4:53/a\nhttp://100.83.3.144/a\nhttp://[2606:4700:4700::1111]:443/a\n"
                "http://127.0.0.1/a\nhttp://[::1]/a\nhttp://github.com/bad\n",
                encoding="utf-8",
            )
            domains, networks = GEN.parse_urlhaus_hosts(source)
        self.assertEqual(domains, {"evil.example"})
        self.assertIn("IP-CIDR,8.8.4.4/32,no-resolve", networks)
        self.assertIn("IP-CIDR6,2606:4700:4700::1111/128,no-resolve", networks)
        self.assertNotIn("IP-CIDR,127.0.0.1/32,no-resolve", networks)
        self.assertNotIn("IP-CIDR,100.83.3.144/32,no-resolve", networks)

    def test_urlhaus_keeps_exact_hosts_without_parent_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "urlhaus.txt"
            source.write_text(
                "http://mediafire.com/a\nhttp://download1532.mediafire.com/b\n",
                encoding="utf-8",
            )
            domains, networks = GEN.parse_urlhaus_hosts(source)
        self.assertEqual(domains, {"mediafire.com", "download1532.mediafire.com"})
        self.assertEqual(networks, set())

    def test_adblock_parser_handles_important_rules_and_exceptions(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "filter.txt"
            source.write_text(
                "||bare.example^\n"
                "||important.example^$important,domain=foo.example\n"
                "||script.example^$script\n"
                "||third-party.example^$third-party\n"
                "@@||allowed.example^\n"
                "@@|legacy-allowed.example^|\n",
                encoding="utf-8",
            )
            self.assertEqual(GEN.parse_adblock(source), {"bare.example", "important.example"})
            self.assertEqual(GEN.parse_adblock_exceptions(source), {"allowed.example", "legacy-allowed.example"})

    def test_dedupe_checks_every_ancestor(self):
        self.assertEqual(GEN.dedupe_by_ancestor({"a.b.example.com", "example.com"}), {"example.com"})

    def test_force_direct_domains_must_stay_declared_in_policy_source(self):
        rules = GEN.parse_policy_source(ROOT / "rules/policy.list")
        GEN.verify_force_direct(rules)
        broken = [(group, policy, body) for group, policy, body in rules
                  if body != "DOMAIN-SUFFIX,volces.com"]
        with self.assertRaisesRegex(RuntimeError, "volces.com"):
            GEN.verify_force_direct(broken)
        # Clash 脚本必须内联同一份例外集合，否则客户端之间会分叉。
        script = (ROOT / "clash/clash-verge-script.js").read_text(encoding="utf-8")
        inlined = set(re.findall(r'"DOMAIN-SUFFIX,([^"]+),DIRECT"', script))
        apple_direct = {body.split(",", 1)[1] for _, policy, body in rules
                        if policy == "APPLE-CN" and body.startswith("DOMAIN-SUFFIX,")}
        self.assertTrue(set(GEN.FORCE_DIRECT_DOMAINS).issubset(inlined))
        self.assertEqual(inlined - set(GEN.FORCE_DIRECT_DOMAINS) - apple_direct, set())

    def test_geosite_regex_expansion_is_bounded_and_verified(self):
        self.assertEqual(
            GEN.geosite_rules(GEN.TYPE_REGEX, r"(^|\.)18jmttios[0-9]{2}\.com$"),
            [f"DOMAIN-SUFFIX,18jmttios{index:02d}.com" for index in range(100)],
        )
        self.assertEqual(GEN.geosite_rules(GEN.TYPE_REGEX, r"^chatgpt-\S+\.webpubsub\.azure\.com$"), [])
        self.assertEqual(GEN.geosite_rules(GEN.TYPE_REGEX, r"(^|\.)apiproxy-.+\.amazonaws\.com$"), [])
        # 展开结果必须仍是原正则真正匹配的域名，不得凭空放宽；单标签与超长展开被拒绝。
        self.assertEqual(GEN.geosite_rules(GEN.TYPE_REGEX, r"^nope\.invalid$"), ["DOMAIN-SUFFIX,nope.invalid"])
        self.assertEqual(GEN.geosite_rules(GEN.TYPE_REGEX, r"^single$"), [])
        self.assertEqual(GEN.geosite_rules(GEN.TYPE_REGEX, r"(^|\.)x{20,}\.com$"), [])
        self.assertEqual(GEN.geosite_rules(GEN.TYPE_DOMAIN, "example.com"), ["DOMAIN-SUFFIX,example.com"])

    def test_protobuf_unknown_fields_and_bounds(self):
        domain = b"\x08\x00\x12\x03foo" + b"\x1d\x00\x00\x00\x00"
        self.assertEqual(GEN.parse_domain(domain), (GEN.TYPE_PLAIN, "foo"))
        self.assertEqual(GEN.geosite_rule(GEN.TYPE_PLAIN, "foo"), "DOMAIN-KEYWORD,foo")
        with self.assertRaises(ValueError):
            list(GEN.fields(b"\x0a\x05x"))

    def test_policy_source_and_sensitive_precedence(self):
        rules = GEN.parse_policy_source(ROOT / "rules/policy.list")
        policies = {body: policy for _, policy, body in rules}
        for domain in ("dashscope-intl.aliyuncs.com", "alibabacloud.com", "z.ai", "minimax.io",
                       "moonshot.ai", "tencentcloud.com", "bigo.tv"):
            self.assertEqual(policies[f"DOMAIN-SUFFIX,{domain}"], "SENSITIVE")
        force_direct = ("volcengine.com", "volcengine.net", "volcengineapi.com", "volcengine-api.com",
                        "volces.com", "volceapi.com", "volccdn.com", "volcdns.com", "volcvideo.com",
                        "volcimagex.com", "byteimg.com", "ibytedtos.com")
        for domain in force_direct:
            self.assertEqual(policies[f"DOMAIN-SUFFIX,{domain}"], "DIRECT")
        for body, policy in {
            "DOMAIN-SUFFIX,auth0.com": "SENSITIVE",
            "DOMAIN-KEYWORD,chatgpt-async-webps-prod-": "SENSITIVE",
            "DOMAIN-SUFFIX,prod.hosts.ooklaserver.net": "REJECT",
            "DOMAIN-KEYWORD,apiproxy-device-prod-nlb-": "PROXY",
            "DOMAIN-KEYWORD,dualstack.ichnaea-web-": "PROXY",
        }.items():
            self.assertEqual(policies[body], policy)
        groups = {body: group for group, _, body in rules}
        self.assertEqual(groups["IP-CIDR6,ff00::/8,no-resolve"], "PRIVATE")
        sensitive = next(i for i, (_, policy, _) in enumerate(rules) if policy == "SENSITIVE")
        cn = next(i for i, (_, _, body) in enumerate(rules) if body == "GEOSITE,cn")
        self.assertLess(sensitive, cn)

    def test_domain_matcher_requires_suffix_boundaries(self):
        self.assertTrue(domain_matches("DOMAIN", "apps.apple.com", "apps.apple.com"))
        self.assertFalse(domain_matches("DOMAIN", "apps.apple.com", "buy.apps.apple.com"))
        self.assertTrue(domain_matches("DOMAIN-SUFFIX", "apps.apple.com", "buy.apps.apple.com"))
        self.assertTrue(domain_matches("DOMAIN-KEYWORD", "weather-map", "weather-map.apple.com"))
        for host in ("apple.com.evil.example", "notapple.com", "apps.apple.com.evil.example"):
            with self.subTest(host=host):
                self.assertFalse(domain_matches("DOMAIN-SUFFIX", "apple.com", host))

    def test_apple_policy_targets_and_precedence(self):
        rules = GEN.parse_policy_source(ROOT / "rules/policy.list")
        positions = {}
        for index, (group, policy, _) in enumerate(rules):
            positions.setdefault(group, []).append(index)
            if policy in {"APPLE-CN", "APPLE-PROXY"}:
                self.assertEqual(group, policy)
        for earlier, later in (("REJECT", "APPLE-PROXY"), ("PRIVATE", "APPLE-PROXY"),
                               ("SENSITIVE", "APPLE-PROXY"), ("APPLE-PROXY", "APPLE-CN"),
                               ("APPLE-CN", "DIRECT"), ("APPLE-CN", "DIRECT-PREFERRED"),
                               ("APPLE-CN", "PROXY")):
            with self.subTest(earlier=earlier, later=later):
                self.assertIn(earlier, positions)
                self.assertIn(later, positions)
                self.assertLess(max(positions[earlier]), min(positions[later]))
        apple = {policy: [body.split(",") for _, target, body in rules if target == policy]
                 for policy in ("APPLE-CN", "APPLE-PROXY")}
        for policy, hosts in (("APPLE-CN", APPLE_CN_HOSTS), ("APPLE-PROXY", APPLE_PROXY_HOSTS)):
            for host in hosts:
                with self.subTest(policy=policy, host=host):
                    self.assertTrue(any(domain_matches(rule[0], rule[1], host) for rule in apple[policy]))
        for host in ("foo.apple.com", "apple.com.evil.example", "apps.apple.com.evil.example",
                     "weather-analytics-events.apple.com"):
            with self.subTest(not_apple_direct=host):
                self.assertFalse(any(domain_matches(rule[0], rule[1], host) for rule in apple["APPLE-CN"]))
        self.assertIn(("DIRECT", "DIRECT", "DOMAIN-SUFFIX,icloud-content.com"), rules)
        for host in APPLE_RELAY_HOSTS:
            with self.subTest(exact_relay=host):
                self.assertIn(("APPLE-PROXY", "APPLE-PROXY", f"DOMAIN,{host}"), rules)
                self.assertFalse(any(domain_matches(rule[0], rule[1], "unrelated." + host)
                                     for rule in apple["APPLE-PROXY"]))
        for host in ("unrelated.cloudflare.com", "unrelated.fastly-edge.com"):
            self.assertFalse(any(domain_matches(rule[0], rule[1], host) for rule in apple["APPLE-PROXY"]))

    def test_apple_generated_providers_and_client_precedence(self):
        rules = GEN.parse_policy_source(ROOT / "rules/policy.list")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            GEN.write_client_outputs(root, rules)
            for policy, name in (("APPLE-CN", "apple-cn"), ("APPLE-PROXY", "apple-proxy")):
                provider = root / "rules" / f"{name}.list"
                entries = [line.strip() for line in provider.read_text(encoding="utf-8").splitlines()
                           if line.strip() and not line.startswith("#")]
                self.assertEqual(entries, list(dict.fromkeys(body for _, target, body in rules
                                                            if target == policy)))
                self.assertTrue(entries)
            shadow = (root / "shadowrocket/shadowrocket.conf").read_text(encoding="utf-8")
            ordered = ["/rules/reject.list,广告拦截", "/shadowrocket/geosite/ads.list,广告拦截",
                       "IP-CIDR6,ff00::/8,DIRECT,no-resolve", "/rules/sensitive.list,敏感服务",
                       "/shadowrocket/geosite/sensitive.list,敏感服务", "/rules/apple-proxy.list,日常代理",
                       "/rules/apple-cn.list,DIRECT", "/rules/direct.list,DIRECT",
                       "/shadowrocket/geosite/cn.list,DIRECT", "/rules/proxy.list,日常代理",
                       "/shadowrocket/geosite/proxy.list,日常代理"]
            for earlier, later in zip(ordered, ordered[1:]):
                with self.subTest(client="Shadowrocket", earlier=earlier, later=later):
                    self.assertLess(shadow.index(earlier), shadow.index(later))
            legacy = (root / "clash/clash-verge-merge.yaml").read_text(encoding="utf-8")
            for name in ("apple-cn", "apple-proxy"):
                self.assertIn(f"  {name}:\n", legacy)
                self.assertIn(f"url: {GEN.RAW}/rules/{name}.list", legacy)
                self.assertIn(f"path: ./rules/{name}.list", legacy)
            ordered = ["RULE-SET,reject,REJECT", "IP-CIDR6,ff00::/8,DIRECT,no-resolve",
                       "RULE-SET,sensitive,PROXY", "RULE-SET,apple-proxy,PROXY",
                       "RULE-SET,apple-cn,DIRECT", "RULE-SET,direct,DIRECT", "GEOSITE,cn,DIRECT",
                       "RULE-SET,proxy,PROXY"]
            for earlier, later in zip(ordered, ordered[1:]):
                with self.subTest(client="Legacy", earlier=earlier, later=later):
                    self.assertLess(legacy.index(earlier), legacy.index(later))

    def test_actual_shadowrocket_apple_routes_expand_local_rule_sets(self):
        config = (ROOT / "shadowrocket/shadowrocket.conf").read_text(encoding="utf-8")
        entries = shadowrocket_domain_rules(ROOT, config)
        for host, target, provider in [(host, "DIRECT", "apple-cn") for host in APPLE_CN_HOSTS] + [
                (host, "日常代理", "apple-proxy") for host in APPLE_PROXY_HOSTS]:
            with self.subTest(host=host, target=target):
                actual, origin = first_domain_route(entries, host)
                self.assertEqual(actual, target, f"{host} first matched {origin}")
                self.assertEqual(origin, f"rules/{provider}.list", f"{host} must match its explicit Apple policy")
        self.assertEqual(first_domain_route(entries, "foo.apple.com"),
                         ("日常代理", "shadowrocket/geosite/proxy.list"))
        target, origin = first_domain_route(entries, "weather-analytics-events.apple.com")
        self.assertEqual(target, "REJECT", origin)
        self.assertIn(origin, {"rules/reject.list", "shadowrocket/geosite/ads.list"})
        self.assertEqual(first_domain_route(entries, "p42.icloud-content.com")[0], "DIRECT")
        for host in ("apple.com.evil.example", "apps.apple.com.evil.example"):
            with self.subTest(not_apple_direct=host):
                # FINAL,DIRECT 仍可能适用；负例检查不能误命中 Apple 直连名单。
                self.assertNotEqual(first_domain_route(entries, host)[1], "rules/apple-cn.list")
                self.assertFalse(any(origin == "rules/apple-cn.list" and domain_matches(kind, value, host)
                                     for kind, value, _, origin in entries))

    def test_clash_script_declares_apple_providers_and_precedence(self):
        script = (ROOT / "clash/clash-verge-script.js").read_text(encoding="utf-8")
        declaration = re.search(r"for \(const name of \[([\s\S]*?)\]\)", script)
        self.assertIsNotNone(declaration)
        providers = re.findall(r'"([^"\n]+)"', declaration.group(1))
        for name in ("apple-cn", "apple-proxy"):
            self.assertEqual(providers.count(name), 1)
        self.assertIn('config["rule-providers"][name] = provider(name)', script)
        self.assertIn('format: "text"', script)
        self.assertIn('url: `${RAW}/rules/${name}.list`', script)
        block = script.split("config.rules = [", 1)[1].split("];", 1)[0]
        rules = re.findall(r'"([^"\n]+)"', block)
        ordered = ["RULE-SET,reject,广告拦截", "GEOSITE,category-ads-all,广告拦截",
                   "IP-CIDR6,ff00::/8,DIRECT,no-resolve", "RULE-SET,sensitive,敏感服务",
                   "GEOSITE,anthropic,敏感服务", "RULE-SET,apple-proxy,日常代理",
                   "RULE-SET,apple-cn,DIRECT", "RULE-SET,direct,DIRECT", "GEOSITE,cn,DIRECT",
                   "RULE-SET,proxy,日常代理", "GEOSITE,geolocation-!cn,日常代理"]
        for earlier, later in zip(ordered, ordered[1:]):
            with self.subTest(earlier=earlier, later=later):
                self.assertLess(rules.index(earlier), rules.index(later))

    def test_private_policy_must_be_direct(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "policy.list"
            source.write_text("IP-CIDR,10.0.0.0/8,REJECT,no-resolve\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "private networks must use DIRECT"):
                GEN.parse_policy_source(source)

    def test_geosite_generation_handles_normalized_categories_and_sensitive_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dat_dir = root / "upstream"
            dat_dir.mkdir()
            geosite_fixture(dat_dir / "geosite.dat", {
                "CN": ["cn.example"],
                "OPENAI": ["openai.example"],
                "ANTHROPIC": ["anthropic.example"],
                "CATEGORY-ADS-ALL": ["ads.example"],
                "GFW": ["proxy.example"],
                "PREFERRED": ["preferred.example"],
            })
            geoip_cn_fixture(dat_dir / "geoip.dat")
            for name in ("anti-ad-domains.txt", "adguard-filter.txt", "adrules.txt", "urlhaus.txt"):
                (dat_dir / name).write_text("", encoding="utf-8")
            rules = [
                ("REJECT", "REJECT", "GEOSITE,category-ads-all"),
                ("DIRECT", "DIRECT", "GEOSITE,cn"),
                ("SENSITIVE", "SENSITIVE", "GEOSITE,openai"),
                ("SENSITIVE", "SENSITIVE", "GEOSITE,anthropic"),
                ("PROXY", "PROXY", "GEOSITE,gfw"),
                ("DIRECT-PREFERRED", "DIRECT-PREFERRED", "GEOSITE,preferred"),
            ]
            GEN.generate_upstream(root, dat_dir, rules)
            sensitive = (root / "shadowrocket/geosite/sensitive.list").read_text(encoding="utf-8")
            self.assertIn("DOMAIN-SUFFIX,openai.example", sensitive)
            self.assertIn("DOMAIN-SUFFIX,anthropic.example", sensitive)
            self.assertIn("DOMAIN-SUFFIX,proxy.example", (root / "shadowrocket/geosite/proxy.list").read_text(encoding="utf-8"))
            self.assertIn("DOMAIN-SUFFIX,preferred.example", (root / "shadowrocket/geosite/direct-preferred.list").read_text(encoding="utf-8"))

    def test_client_generation_is_idempotent(self):
        rules = GEN.parse_policy_source(ROOT / "rules/policy.list")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rules").mkdir()
            for name in ("ads-extra.list", "malware.list"):
                shutil.copyfile(ROOT / "rules" / name, root / "rules" / name)
            GEN.write_client_outputs(root, rules)
            before = {path.relative_to(root): hashlib.sha256(path.read_bytes()).digest()
                      for path in root.rglob("*") if path.is_file()}
            GEN.write_client_outputs(root, rules)
            after = {path.relative_to(root): hashlib.sha256(path.read_bytes()).digest()
                     for path in root.rglob("*") if path.is_file()}
            self.assertIn(Path("rules/apple-cn.list"), before)
            self.assertIn(Path("rules/apple-proxy.list"), before)
            self.assertEqual(before, after)
            provider = (root / "clash/rule-provider.yaml").read_text(encoding="utf-8")
            self.assertIn("payload:", provider)
            self.assertIn("GEOSITE,category-porn", provider)
            shadow = (root / "shadowrocket/shadowrocket.conf").read_text(encoding="utf-8")
            self.assertLess(shadow.index("DOMAIN-SUFFIX,volces.com,DIRECT"), shadow.index("/rules/reject.list"))
            self.assertIn("/shadowrocket/geosite/sensitive.list,敏感服务", shadow)
        script = (ROOT / "clash/clash-verge-script.js").read_text(encoding="utf-8")
        for category in ("geolocation-!cn", "google", "youtube", "telegram", "facebook", "twitter", "instagram",
                         "whatsapp", "discord", "reddit", "netflix", "spotify", "twitch"):
            self.assertIn(f'"GEOSITE,{category},日常代理"', script)
        self.assertIn('"IP-CIDR6,ff00::/8,DIRECT,no-resolve"', script)
        for domain in ("volcengine.com", "volcengine.net", "volcengineapi.com", "volcengine-api.com",
                       "volces.com", "volceapi.com", "volccdn.com", "volcdns.com", "volcvideo.com",
                       "volcimagex.com", "byteimg.com", "ibytedtos.com"):
            self.assertIn(f'"DOMAIN-SUFFIX,{domain},DIRECT"', script)


if __name__ == "__main__":
    unittest.main()
