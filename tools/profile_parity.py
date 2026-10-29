# -*- coding: utf-8 -*-
"""真实指纹 + 固定 pin 下，Python 与 Rust 的 t / so 逐字节对拍。

    python tools/profile_parity.py
"""
import hashlib
import json
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
# Python oracle 目录只从环境变量读，没有绝对默认值。
PY_DIR = os.environ.get("SENTINEL_PY_DIR") or os.environ.get("SENTINEL_ORACLE_DIR")
SAMPLE = os.path.join(PROJ, "sample_challenge.json")
EXE = os.path.join(PROJ, "target", "release", "profile_mint.exe")

NOW_MS = 1_793_036_746_210.0
PERF = 15.5


def _prepare():
    sys.path.insert(0, PY_DIR)
    import sentinel_py as sp
    import sentinel_vm as vm

    import time as _time

    random.random = lambda: 0.5
    _time.time = lambda: NOW_MS / 1000.0

    blob = json.load(open(SAMPLE, encoding="utf-8"))
    profile = sp._profile_from_fingerprint(blob.get("fp") or {})
    return sp, vm, blob, profile


def _pinned_vm(vm, profile):
    ctx = vm.VM(profile=profile, device_id="pinned")
    ctx.window["Date"] = {"now": lambda: NOW_MS}
    ctx.window["performance"] = type(
        "P",
        (),
        {
            "now": lambda self=None: PERF,
            "timeOrigin": NOW_MS - PERF,
            "getEntriesByType": lambda self=None, *a: [],
            "getEntriesByName": lambda self=None, *a: [],
            "mark": lambda self=None, *a: None,
            "measure": lambda self=None, *a: None,
        },
    )()
    return ctx


def python_tokens():
    sp, vm, blob, profile = _prepare()
    p = blob["p"]
    ctx = _pinned_vm(vm, profile)
    sp._run_program(blob["challenge"]["turnstile"]["dx"], p, ctx)
    t = ctx.out or ""

    so_block = (blob["challenge"].get("so") or {})
    so = ""
    if so_block.get("collector_dx"):
        ctx = _pinned_vm(vm, profile)
        sp._run_program(so_block["collector_dx"], p, ctx)
        sp._dispatch_behavior(ctx, profile, 0)
        ctx.done = False
        ctx.out = None
        ctx.err = None
        ctx.set(9, vm.load_program(so_block["snapshot_dx"], p))
        ctx.run_queue()
        so = ctx.out or ""
    return t, so


def rust_token(args):
    if not os.path.exists(EXE):
        return None
    proc = subprocess.run(
        [EXE, SAMPLE] + args,
        cwd=PROJ,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if proc.returncode != 0:
        print("rust 失败:", proc.stderr[:400])
        return None
    return proc.stdout.strip()


def check(name, py, rs):
    if rs is None:
        print(f"{name}: rust 未构建（cargo build --release --bin profile_mint）")
        return False
    a = hashlib.sha256(py.encode()).hexdigest()
    b = hashlib.sha256(rs.encode()).hexdigest()
    ok = py == rs
    print(f"{name}: python len={len(py)} {a[:16]}  rust len={len(rs)} {b[:16]}  {'OK' if ok else 'DIFF'}")
    if not ok:
        idx = next((i for i in range(min(len(py), len(rs))) if py[i] != rs[i]), -1)
        print(f"  首个差异位置={idx}")
    return ok


def main():
    py_t, py_so = python_tokens()
    rs_t = rust_token([])
    rs_so = rust_token(["--so"])
    ok_t = check("t ", py_t, rs_t)
    ok_so = check("so", py_so, rs_so)
    print("RESULT:", "PASS（真实指纹下 t/so 逐字节相同）" if (ok_t and ok_so) else "FAIL")
    return 0 if (ok_t and ok_so) else 1


if __name__ == "__main__":
    sys.exit(main())
