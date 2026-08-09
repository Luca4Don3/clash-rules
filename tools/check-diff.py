#!/usr/bin/env python3
"""检查生成产物相对 HEAD 的变动是否可疑(疑似上游异常时拒绝自动推送)。

用法:在仓库根目录运行,有异常时 exit 1(供 CI 使用)。
"""
import os
import subprocess
import sys

# (文件, 单次新增上限, 单次削减比例上限)
WATCH = [
    ("rules/ads-extra.list", 5000, 0.20),
    ("rules/malware.list", 2000, 0.50),
    ("shadowrocket/geosite/cn.list", 3000, 0.20),
    ("shadowrocket/geosite/proxy.list", 1000, 0.20),
]


def head_lines(path):
    r = subprocess.run(["git", "show", f"HEAD:{path}"], capture_output=True, text=True)
    if r.returncode != 0:
        return 0
    return r.stdout.count("\n")


def cur_lines(path):
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as f:
        return sum(1 for _ in f)


def main():
    issues = []
    for path, max_add, max_cut in WATCH:
        old = head_lines(path)
        new = cur_lines(path)
        if old <= 0:
            continue
        if new - old > max_add:
            issues.append(f"{path}: 新增 {new - old} 行(阈值 {max_add})")
        if new < old * (1 - max_cut):
            issues.append(f"{path}: 减少 {old - new} 行(超过 {int(max_cut * 100)}%)")
    if issues:
        print("[异常] 检测到可疑变化:")
        for i in issues:
            print(f"  - {i}")
        return 1
    print("diff 检查通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
