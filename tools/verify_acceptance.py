# -*- coding: utf-8 -*-
"""端到端验收：直接调用**发布版二进制**，与 Python oracle 逐字节比对。

    python tools/verify_acceptance.py

检查项：
  1. `cargo build --release` 产物能跑通
  2. `sentinel-rs mint --file sample_challenge.json --run-vm` 打印 steps = 426
  3. 该二进制打印出的 `t`（mint 产线路径）与 Python oracle 的 t **完全相等**
  4. VM 内联路径（`t head` / `VM: steps`）与产线路径一致
"""
import hashlib
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)

import pyoracle  # noqa: E402

EXE = os.path.join(PROJ, "target", "release", "sentinel-rs.exe")
EXPECT_STEPS = 426


def run_bin():
    proc = subprocess.run(
        [EXE, "mint", "--file", "sample_challenge.json", "--run-vm", "--oracle-env"],
        cwd=PROJ,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def main():
    if not os.path.exists(EXE):
        print(f"FAIL: 找不到 {EXE}（先 cargo build --release）")
        return 1
    code, out, err = run_bin()
    if code != 0:
        print(f"FAIL: 退出码 {code}\n{err}")
        return 1

    m_int = re.search(r"t 长度 = (\d+)", out)
    m_steps = re.search(r"VM: steps = (\d+)\s+t_len = (\d+)", out)
    t_lines = [ln for ln in out.splitlines() if re.fullmatch(r"[A-Za-z0-9+/=]{40,}", ln.strip())]

    if not m_steps:
        print("FAIL: 没有找到 `VM: steps = ...` 行")
        print(out)
        return 1
    steps, vmt_len = int(m_steps.group(1)), int(m_steps.group(2))
    mint_t = t_lines[0].strip() if t_lines else ""
    mint_len = int(m_int.group(1)) if m_int else -1

    vm = pyoracle.run()
    py_t = vm.out or ""
    py_steps = vm.steps

    ok = True
    print(f"binary            : {EXE}")
    print(f"python steps      : {py_steps}")
    print(f"rust   steps      : {steps}")
    print(f"python t len      : {len(py_t)}")
    print(f"rust   t len      : mint={mint_len} vm={vmt_len} line={len(mint_t)}")
    print(f"python t sha256   : {hashlib.sha256(py_t.encode()).hexdigest()}")
    print(f"rust   t sha256   : {hashlib.sha256(mint_t.encode()).hexdigest()}")

    if py_steps != EXPECT_STEPS:
        print(f"FAIL: python steps != {EXPECT_STEPS}")
        ok = False
    if steps != EXPECT_STEPS:
        print(f"FAIL: rust steps != {EXPECT_STEPS}")
        ok = False
    if mint_len != len(py_t) or vmt_len != len(py_t):
        print("FAIL: t 长度不一致")
        ok = False
    if mint_t != py_t:
        print("FAIL: t 内容不一致")
        idx = next((i for i in range(min(len(mint_t), len(py_t))) if mint_t[i] != py_t[i]), -1)
        print(f"  首个差异位置 = {idx}")
        ok = False
    head = re.search(r"t head = (\S+)", out)
    if head and not py_t.startswith(head.group(1)):
        print("FAIL: `t head` 与 python t 前缀不一致")
        ok = False

    print("RESULT:", "PASS (steps=426, t byte-identical)" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
