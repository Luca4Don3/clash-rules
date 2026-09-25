#!/usr/bin/env python3
"""用合成机场配置验证扩展脚本、Mihomo 配置与 provider API。"""

import argparse
import json
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def expand_script(node_binary="node"):
    node = r'''
const fs = require("fs"), vm = require("vm");
const context = {}; vm.createContext(context);
vm.runInContext(fs.readFileSync("clash/clash-verge-script.js", "utf8"), context);
const input = {proxies:[{name:"测试节点",type:"ss",server:"127.0.0.1",port:443,cipher:"aes-128-gcm",password:"test"}],"proxy-providers":{},"proxy-groups":[{name:"PROXY",type:"select",proxies:["测试节点"]}],rules:["MATCH,PROXY"]};
const once = context.main(JSON.parse(JSON.stringify(input)));
const twice = context.main(JSON.parse(JSON.stringify(once)));
if (JSON.stringify(once) !== JSON.stringify(twice)) throw new Error("not idempotent");
process.stdout.write(JSON.stringify(once));
'''
    return json.loads(subprocess.run([node_binary, "-e", node], cwd=ROOT, check=True,
                                     capture_output=True, text=True).stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mihomo", default=".temp/mihomo")
    parser.add_argument("--node", default="node", help="Node.js executable used to expand the extension script")
    args = parser.parse_args()
    binary = (ROOT / args.mihomo).resolve()
    if not binary.is_file():
        raise RuntimeError(f"Mihomo binary not found: {binary}")
    home = ROOT / ".temp/mihomo-home"
    home.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / ".temp/upstream/geosite.dat", home / "geosite.dat")
    shutil.copyfile(ROOT / ".temp/upstream/geoip.dat", home / "geoip.dat")
    provider_dir = home / "rules"
    provider_dir.mkdir(exist_ok=True)

    config = expand_script(args.node)
    for name, provider in config["rule-providers"].items():
        local_provider = provider_dir / f"{name}.list"
        shutil.copyfile(ROOT / "rules" / f"{name}.list", local_provider)
        provider.update(type="file", path=str(local_provider))
        provider.pop("url", None)
        provider.pop("interval", None)
    config.update({"mixed-port": 0, "external-controller": "127.0.0.1:19090",
                   "log-level": "silent", "geodata-mode": True})
    path = ROOT / ".temp/synthetic.yaml"
    # Mihomo accepts JSON as a YAML subset; avoid making the integration gate depend on PyYAML.
    path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    subprocess.run([str(binary), "-d", str(home), "-f", str(path), "-t"], check=True)

    process = subprocess.Popen([str(binary), "-d", str(home), "-f", str(path)],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        last_error = None
        providers = None
        for _ in range(200):
            try:
                with urllib.request.urlopen("http://127.0.0.1:19090/providers/rules", timeout=1) as response:
                    payload = json.load(response)
                candidate = payload.get("providers", payload) if isinstance(payload, dict) else None
                if (isinstance(candidate, dict) and candidate and
                        all(candidate.get(name, {}).get("ruleCount", 0) > 0 for name in config["rule-providers"])):
                    providers = candidate
                    break
                last_error = RuntimeError("provider registry is not ready")
            except OSError as error:
                last_error = error
            if process.poll() is not None:
                raise RuntimeError(process.stdout.read())
            time.sleep(0.1)
        else:
            raise RuntimeError(f"Mihomo API did not start: {last_error}")
        empty = {name: item.get("ruleCount", 0) for name, item in providers.items()
                 if name in config["rule-providers"] and item.get("ruleCount", 0) <= 0}
        if empty:
            raise RuntimeError(f"empty rule providers: {empty}")
        print("Mihomo API provider ruleCount:",
              {name: providers[name]["ruleCount"] for name in config["rule-providers"]})
    finally:
        process.terminate()
        process.wait(timeout=5)


if __name__ == "__main__":
    main()
