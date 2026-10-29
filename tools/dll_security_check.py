# -*- coding: utf-8 -*-
"""静态安全性检查：原版 DLL vs VMProtect 加壳版（两组路径都从环境变量读）。

    $env:SRS_DLL     = "<repo>/target/release/sentinel_rs.dll"   # 原版
    $env:SRS_DLL_VMP = "<某处>/sentinel_rs.vmp.dll"              # 加壳版

没设置的组会跳过（只打印提示），不会回退到任何绝对路径。
"""
import hashlib
import math
import os
import re
import sys

import pefile

FILES = {}
if os.environ.get("SRS_DLL"):
    FILES["原版"] = os.environ["SRS_DLL"]
if os.environ.get("SRS_DLL_VMP"):
    FILES["VMP "] = os.environ["SRS_DLL_VMP"]

SENSITIVE = [
    "auth.openai.com", "chatgpt.com", "api.openai.com", "/api/accounts/user/register",
    "/api/accounts/email-otp", "sentinel.openai.com", "requirements", "turnstile",
    "oai-did", "oai-sc", "x-openai-", "sec-ch-ua", "Sentinel", "srs_register",
    "srs_mint_t", "REG_MAIL_API_BASE_URL", "REG_MAIL_API_TOKEN", "socks5h://",
    "invalid_state", "username_password_create", "gAAAAA", "Bearer ",
]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def strings_of(data: bytes, minlen=6):
    out = set()
    for m in re.finditer(rb"[\x20-\x7e]{6,}", data):
        out.add(m.group().decode("latin-1"))
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", data):
        out.add(m.group().decode("utf-16-le", "ignore"))
    return out


def analyze(label, path):
    pe = pefile.PE(path, fast_load=False)
    raw = open(path, "rb").read()
    print(f"\n===== {label} {path} =====")
    print(f"size        : {len(raw):,} B   sha256={hashlib.sha256(raw).hexdigest()[:32]}…")
    print(f"machine     : {hex(pe.FILE_HEADER.Machine)}   链接器 {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}")
    print(f"入口点      : RVA {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
    signed = hasattr(pe, "DIRECTORY_ENTRY_SECURITY")
    print(f"数字签名    : {'有' if signed else '无'}")

    print("\n-- 节区 --")
    print(f"{'名称':<10}{'VA':>10}{'原始大小':>12}{'熵':>7}{'可执行':>7}{'可写':>6}")
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        d = s.get_data()
        print(f"{name:<10}{hex(s.VirtualAddress):>10}{s.SizeOfRawData:>12,}{entropy(d):>7.2f}"
              f"{'Y' if s.Characteristics & 0x20000000 else '-':>7}{'Y' if s.Characteristics & 0x80000000 else '-':>6}")

    print("\n-- 导出 --")
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print(f"  #{e.ordinal:<4} {e.name.decode() if e.name else '(无名)'}  RVA {hex(e.address)}")
    else:
        print("  无")

    print("\n-- 高危导入（前 40）--")
    dlls = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dlls.append(entry.dll.decode())
    print("  DLL:", ", ".join(sorted(dlls)) or "无")

    strs = strings_of(raw)
    print(f"\n-- 字符串统计 -- 共 {len(strs)} 条")
    hits = {}
    for needle in SENSITIVE:
        n = sum(1 for s in strs if needle.lower() in s.lower())
        if n:
            hits[needle] = n
    for k, v in hits.items():
        print(f"  [{v:>3}] {k}")
    if not hits:
        print("  未命中任何敏感标记")

    left = [s for s in strs if any(x in s.lower() for x in ("openai", "sentinel", "srs_", "reg_mail", "turnstile"))]
    print(f"\n-- 残留线索（最多 15 条）--")
    for s in sorted(left)[:15]:
        print("   ", s[:100])
    return {"size": len(raw), "sections": len(pe.sections), "strings": len(strs), "hits": hits}


if __name__ == "__main__":
    if not FILES:
        print("需要设置 SRS_DLL（原版 DLL）和 / 或 SRS_DLL_VMP（加壳版 DLL）后再运行")
        print('  例如：$env:SRS_DLL = "target\\release\\sentinel_rs.dll"')
        sys.exit(1)
    missing = [k for k in ("原版", "VMP ") if k not in FILES]
    for k in missing:
        print(f"[跳过] 未设置 {'SRS_DLL' if k == '原版' else 'SRS_DLL_VMP'}，跳过该组")
    for label, path in FILES.items():
        analyze(label, path)
