# -*- coding: utf-8 -*-
"""动态视角：DLL 跑起来后，同进程内存里还能捞到多少明文（攻击者 dump 内存能看到什么）。"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import re
import sys

CWD = os.getcwd()
# 路径优先取环境变量，缺省值相对**当前工作目录**（在仓库根目录运行即可）。
DLL = os.environ.get("SRS_DLL") or os.path.join(CWD, "target", "release", "sentinel_rs.dll")
SAMPLE = os.environ.get("SRS_SAMPLE") or os.path.join(CWD, "sample_challenge.json")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


MARKERS = [
    b"auth.openai.com",
    b"/api/accounts/user/register",
    b"sentinel.openai.com",
    b"username_password_create",
    b"REG_MAIL_API_BASE_URL",
    b"REG_MAIL_API_TOKEN",
    b"sec-ch-ua",
    b"invalid_state",
    b"Bearer ",
]


def scan_memory():
    pid = k32.GetCurrentProcess()
    addr = 0
    hits = {m: 0 for m in MARKERS}
    mbi = MEMORY_BASIC_INFORMATION()
    max_addr = 0x7FFFFFFF0000
    while addr < max_addr:
        got = k32.VirtualQueryEx(pid, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not got:
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if size == 0:
            break
        if mbi.State == 0x1000 and mbi.Protect in (0x04, 0x02, 0x40, 0x20, 0x80, 0x01):
            buf = ctypes.create_string_buffer(size)
            read = ctypes.c_size_t(0)
            ok = k32.ReadProcessMemory(pid, ctypes.c_void_p(base), buf, size, ctypes.byref(read))
            if ok:
                data = buf.raw[: read.value]
                for m in MARKERS:
                    if m in data:
                        hits[m] += data.count(m)
        addr = base + size
    return hits


def main():
    lib = ctypes.CDLL(DLL)
    lib.srs_version.restype = ctypes.c_void_p
    lib.srs_mint_t.restype = ctypes.c_void_p
    lib.srs_mint_t.argtypes = [ctypes.c_char_p] * 3
    lib.srs_register.restype = ctypes.c_void_p
    lib.srs_register.argtypes = [ctypes.c_char_p]
    lib.srs_free.argtypes = [ctypes.c_void_p]

    def take(p):
        if not p:
            return ""
        s = ctypes.string_at(p).decode("utf-8", "replace")
        lib.srs_free(p)
        return s

    blob = json.load(open(SAMPLE, encoding="utf-8"))
    fp = json.dumps(blob.get("fp") or {}).encode()
    print("version:", take(lib.srs_version()))
    t = take(lib.srs_mint_t(blob["challenge"]["turnstile"]["dx"].encode(), blob["p"].encode(), fp))
    print("mint_t :", len(t), "B")
    dry = take(lib.srs_register(json.dumps({"SENTINEL_PROXY": "", "SENTINEL_COUNT": "1"}).encode()))
    print("dry    :", dry[:80])

    if os.environ.get("SRS_LIVE") == "1":
        live = take(lib.srs_register(json.dumps({
            "SENTINEL_PROXY": "socks5h://127.0.0.1:1080",
            "SENTINEL_COUNT": "1",
            "SENTINEL_LIVE_REGISTER": "1",
            "SENTINEL_ENABLE_2FA": "1",
        }).encode()))
        print("live   :", live[:100])

    print("\n-- 内存扫描（跑完 mint + 注册之后）--")
    hits = scan_memory()
    for k, v in hits.items():
        print(f"  {k.decode():<32} {'命中 %d 处' % v if v else '未出现'}")


if __name__ == "__main__":
    main()
