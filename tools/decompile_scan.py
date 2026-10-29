# -*- coding: utf-8 -*-
"""对原版 DLL 做定向反汇编：定位导出函数 + 关键字符串引用点，输出可读切片。

目标 DLL 用 `SRS_DLL` 指定，缺省相对当前工作目录取 target/release/sentinel_rs.dll。
"""
import os
import sys

import capstone
import pefile

DLL = os.environ.get("SRS_DLL") or os.path.join(
    os.getcwd(), "target", "release", "sentinel_rs.dll"
)
pe = pefile.PE(DLL)
base = pe.OPTIONAL_HEADER.ImageBase

text = next(s for s in pe.sections if s.Name.startswith(b".text"))
rdata = next(s for s in pe.sections if s.Name.startswith(b".rdata"))
raw = open(DLL, "rb").read()
text_bytes = raw[text.PointerToRawData:text.PointerToRawData + text.SizeOfRawData]
text_va = base + text.VirtualAddress
rdata_bytes = raw[rdata.PointerToRawData:rdata.PointerToRawData + rdata.SizeOfRawData]
rdata_va = base + rdata.VirtualAddress

KEYWORDS = [
    b"SENTINEL_LIVE_REGISTER", b"SENTINEL_PROXY", b"SENTINEL_ENABLE_2FA",
    b"/api/accounts/user/register", b"auth.openai.com", b"username_password_create",
    b"REG_MAIL_API_BASE_URL", b"REG_MAIL_API_TOKEN",
]

targets = {}
for kw in KEYWORDS:
    idx = rdata_bytes.find(kw)
    if idx >= 0:
        targets[rdata_va + idx] = kw.decode()
print("字符串 VA:")
for va, kw in targets.items():
    print(f"  {hex(va)}  {kw}")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
hits = {va: [] for va in targets}
count = 0
for insn in md.disasm(text_bytes, text_va):
    count += 1
    for op in insn.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
            tgt = insn.address + insn.size + op.mem.disp
            if tgt in hits:
                hits[tgt].append(insn.address)
print(f"\n扫描 {count:,} 条指令，命中引用点：")
for va, addrs in hits.items():
    print(f"  {targets[va]:<32} {len(addrs)} 处: {', '.join(hex(a) for a in addrs[:6])}")

# 导出函数入口
exports = {e.name.decode(): e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols}

insn_list = [i for i in md.disasm(text_bytes, text_va)]


def dump_window(addr, before=6, after=26, label=""):
    idx = next((i for i, ins in enumerate(insn_list) if ins.address == addr), None)
    if idx is None:
        return
    print(f"\n--- {label} @ {hex(addr)} ---")
    lo = max(0, idx - before)
    hi = min(len(insn_list), idx + after)
    for ins in insn_list[lo:hi]:
        mark = ">>" if ins.address == addr else "  "
        print(f"{mark} {ins.address:#012x}  {ins.mnemonic:<7}{ins.op_str}")


if __name__ == "__main__":
    for name in ("srs_version", "srs_register"):
        va = base + exports[name]
        dump_window(va, before=0, after=22, label=name)
    for va, addrs in hits.items():
        for a in addrs[:1]:
            dump_window(a, before=10, after=16, label=f"引用 {targets[va]}")
