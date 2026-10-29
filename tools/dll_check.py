# -*- coding: utf-8 -*-
"""用 Python ctypes 验证 Rust 注册核心 DLL（sentinel_rs.dll）。"""
import ctypes
import json
import os
import sys

CWD = os.getcwd()
# 路径优先取环境变量，缺省值相对**当前工作目录**（在仓库根目录运行即可）。
DLL = os.environ.get("SRS_DLL") or os.path.join(CWD, "target", "release", "sentinel_rs.dll")
SAMPLE = os.environ.get("SRS_SAMPLE") or os.path.join(CWD, "sample_challenge.json")

lib = ctypes.CDLL(DLL)
lib.srs_version.restype = ctypes.c_void_p
lib.srs_mint_t.restype = ctypes.c_void_p
lib.srs_mint_t.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.srs_mint_so.restype = ctypes.c_void_p
lib.srs_mint_so.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.srs_requirements_token.restype = ctypes.c_void_p
lib.srs_requirements_token.argtypes = [ctypes.c_char_p]
lib.srs_register.restype = ctypes.c_void_p
lib.srs_register.argtypes = [ctypes.c_char_p]
lib.srs_free.argtypes = [ctypes.c_void_p]


def take(ptr):
    if not ptr:
        return ""
    s = ctypes.string_at(ptr).decode("utf-8", "replace")
    lib.srs_free(ptr)
    return s


def main():
    print("version        :", take(lib.srs_version()))

    blob = json.load(open(SAMPLE, encoding="utf-8"))
    p = blob["p"]
    dx = blob["challenge"]["turnstile"]["dx"]
    fp = json.dumps(blob.get("fp") or {}, ensure_ascii=False).encode()

    req = take(lib.srs_requirements_token(fp))
    print("requirements   :", len(req), req[:24] + "...")

    t = take(lib.srs_mint_t(dx.encode(), p.encode(), fp))
    print("t              :", len(t), t[:32] + "...")

    so_block = blob["challenge"].get("so") or {}
    so = ""
    if so_block.get("collector_dx"):
        so = take(lib.srs_mint_so(
            so_block["collector_dx"].encode(),
            so_block["snapshot_dx"].encode(),
            p.encode(), fp))
        print("so             :", len(so), so[:24] + "...")

    if not t.startswith("ERR") and not so.startswith("ERR"):
        print("mint 验证       : PASS（t/so 均非空且无错误）")
    else:
        print("mint 验证       : FAIL")

    cfg = {
        "SENTINEL_PROXY": "socks5h://127.0.0.1:1080",
        "SENTINEL_COUNT": "1",
    }
    out = take(lib.srs_register(json.dumps(cfg).encode()))
    print("register(dry)  :", out[:200])

    live = os.environ.get("SRS_LIVE", "") == "1"
    if live:
        cfg_live = {
            "SENTINEL_PROXY": "socks5h://127.0.0.1:1080",
            "SENTINEL_COUNT": "1",
            "SENTINEL_LIVE_REGISTER": "1",
            "SENTINEL_ENABLE_2FA": "1",
            "SENTINEL_DB_PATH": os.path.join(CWD, "data", "sentinel-rs.db"),
            "OTP_MAX_WAIT": "150",
            "OTP_POLL_INTERVAL": "3",
        }
        out_live = take(lib.srs_register(json.dumps(cfg_live).encode()))
        print("register(live) :", out_live[:300])
        return 0 if out_live.startswith("{") else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
