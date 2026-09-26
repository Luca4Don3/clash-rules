import hashlib
import importlib.util
import ipaddress
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

    def test_dedupe_checks_every_ancestor(self):
        self.assertEqual(GEN.dedupe_by_ancestor({"a.b.example.com", "example.com"}), {"example.com"})

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
            paths = [root / "clash/clash-verge-merge.yaml", root / "clash/rule-provider.yaml",
                     root / "shadowrocket/shadowrocket.conf"] + list((root / "rules").glob("*.list"))
            before = {path: hashlib.sha256(path.read_bytes()).digest() for path in paths}
            GEN.write_client_outputs(root, rules)
            after = {path: hashlib.sha256(path.read_bytes()).digest() for path in paths}
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
