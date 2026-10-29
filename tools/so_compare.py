# -*- coding: utf-8 -*-
"""SO token（session observer）对拍：Python oracle vs Rust `so_check`。

两边都跑同一份 sample_challenge.json：

    collector_dx -> dispatch_behavior -> snapshot_dx -> so

固定 pin（与 tools/pyoracle.py 完全一致，Rust 侧对应 vm.rs / env_dump.json）：

    Date.now()        = 1700000000000
    performance.now() = 15.5
    Math.random()     = 0.5        -> Rust: token::Rng::constant(0.5)
    randint(a, b)     = a          -> __oai_so_* 取下界
    urandom(n)        = b"\\x00" * n
    uuid4()           = 00000000-0000-4000-8000-000000000000

用法：
    python tools/so_compare.py              # 有 target/release/so_check.exe 就直接用
    python tools/so_compare.py --build      # 先 cargo build --release --bin so_check
    python tools/so_compare.py --py-only    # 只跑 Python 侧（打印基线）
"""
from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import time as _time

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import pyoracle  # noqa: E402

EXE = os.path.join(PROJ, "target", "release", "so_check.exe")
EXE_UNIX = os.path.join(PROJ, "target", "release", "so_check")


# ------------------------------------------------------------------ Python 侧

def py_so(challenge_path: str = "") -> tuple[str, int, str]:
    """按 sentinel_py.get_sentinel_token_py 的 SO 分支跑一遍，返回 (so, steps, err)。"""
    vm_mod = pyoracle.patch()
    import sentinel_py  # noqa: WPS433  (必须 patch 之后再导入/使用)

    # _dispatch_behavior 里的 time.sleep 只是节流，对 VM 语义没有任何影响；
    # 打桩掉可以把 2~3 秒的对拍压到毫秒级。
    _time.sleep = lambda _s: None

    blob = pyoracle.load_challenge(challenge_path or pyoracle.SAMPLE)
    p = blob["p"]
    so_block = blob["challenge"]["so"]
    if not so_block.get("collector_dx") or not so_block.get("snapshot_dx"):
        raise SystemExit("sample_challenge.json 里没有 so.collector_dx / so.snapshot_dx")

    ctx = pyoracle.new_vm(profile={}, device_id="x")
    ctx.set(16, p)
    ctx.set(9, vm_mod.load_program(so_block["collector_dx"], p))
    ctx.run_queue()

    sentinel_py._dispatch_behavior(ctx, {})

    ctx.done = False
    ctx.out = None
    ctx.err = None
    ctx.set(9, vm_mod.load_program(so_block["snapshot_dx"], p))
    ctx.run_queue()

    return ctx.out or "", ctx.steps, (ctx.err or "")


# -------------------------------------------------------------------- Rust 侧

def rust_so(build: bool = False, exe_path: str = "") -> tuple[str, int, str, str]:
    """跑 target/release/so_check（或 cargo run），返回 (so, steps, sha256, raw)。"""
    exe = exe_path or (EXE if os.path.exists(EXE) else EXE_UNIX)
    if build or not os.path.exists(exe):
        print("[compare] cargo build --release --bin so_check ...", flush=True)
        subprocess.run(
            ["cargo", "build", "--release", "--bin", "so_check"],
            cwd=PROJ, check=True,
        )
        exe = EXE if os.path.exists(EXE) else EXE_UNIX

    proc = subprocess.run([exe], cwd=PROJ, capture_output=True, text=True, encoding="utf-8")
    if proc.returncode != 0:
        raise SystemExit(f"so_check 失败 (exit={proc.returncode})\n{proc.stdout}\n{proc.stderr}")
    out = proc.stdout
    fields = {}
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            fields[parts[0]] = parts[1].strip()
    return (
        fields.get("so", ""),
        int(fields.get("steps", "-1")),
        fields.get("sha256", ""),
        out,
    )


# ---------------------------------------------------------------------- 对比

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def first_diff(a: str, b: str) -> int:
    """逐字节（UTF-8）第一处差异的下标；None = 完全相同。"""
    ba, bb = a.encode("utf-8"), b.encode("utf-8")
    for i in range(min(len(ba), len(bb))):
        if ba[i] != bb[i]:
            return i
    return None if len(ba) == len(bb) else min(len(ba), len(bb))


def describe_diff(a: str, b: str, idx: int, ctx: int = 40) -> str:
    ba, bb = a.encode("utf-8"), b.encode("utf-8")

    def window(buf: bytes) -> str:
        lo, hi = max(0, idx - ctx), min(len(buf), idx + ctx)
        return buf[lo:hi].decode("utf-8", "replace").replace("\n", "\\n")

    return (
        f"  first-diff = {idx}  (py_len={len(ba)} rs_len={len(bb)})\n"
        f"  py …{window(ba)}…\n"
        f"  rs …{window(bb)}…"
    )


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge", default="", help="challenge JSON（默认 sample_challenge.json）")
    ap.add_argument("--build", action="store_true", help="先 cargo build --release --bin so_check")
    ap.add_argument("--exe", default="", help="指定 so_check 可执行文件（默认 target/release/）")
    ap.add_argument("--py-only", action="store_true", help="只跑 Python 侧")
    args = ap.parse_args(argv)

    print("[compare] pins: Date.now=1700000000000 performance.now=15.5 random.random=0.5")
    py_so_text, py_steps, py_err = py_so(args.challenge)
    py_hash = sha256(py_so_text)
    print(f"[python] so_len={len(py_so_text)} sha256={py_hash} steps={py_steps} err={py_err or '-'}")
    if args.py_only:
        return 0

    rs_so_text, rs_steps, rs_hash, _raw = rust_so(build=args.build, exe_path=args.exe)
    print(f"[rust]   so_len={len(rs_so_text)} sha256={rs_hash} steps={rs_steps}")

    ok = True
    if py_hash != rs_hash:
        ok = False
        idx = first_diff(py_so_text, rs_so_text)
        print("[FAIL] so sha256 不一致")
        if idx is not None:
            print(describe_diff(py_so_text, rs_so_text, idx))
    if py_steps != rs_steps:
        ok = False
        print(f"[FAIL] steps 不一致：python={py_steps} rust={rs_steps}")

    if ok:
        print(f"[OK] so byte-identical: len={len(py_so_text)} sha256={py_hash} "
              f"first-diff=None steps={py_steps}")
        return 0
    print("[FAIL] so mismatch (see diff above)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
