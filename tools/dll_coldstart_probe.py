# -*- coding: utf-8 -*-
"""冷启动模拟：只拿到 DLL、没有任何文档的人，能试探出什么。"""
import ctypes
import json
import os

DLL = os.environ.get("SRS_DLL") or os.path.join(
    os.getcwd(), "target", "release", "sentinel_rs.dll"
)
lib = ctypes.CDLL(DLL)

SIGS = {
    "srs_version": [],
    "srs_mint_t": ["s", "s", "s"],
    "srs_mint_so": ["s", "s", "s", "s"],
    "srs_requirements_token": ["s"],
    "srs_register": ["s"],
}
for name, args in SIGS.items():
    fn = getattr(lib, name)
    fn.restype = ctypes.c_void_p
    if args:
        fn.argtypes = [ctypes.c_char_p] * len(args)
lib.srs_free.argtypes = [ctypes.c_void_p]


def take(p):
    if not p:
        return "(null)"
    s = ctypes.string_at(p).decode("utf-8", "replace")
    lib.srs_free(p)
    return s


CASES = [
    ("srs_version()", lambda: take(lib.srs_version())),
    ("srs_register('{}')", lambda: take(lib.srs_register(b"{}"))),
    ("srs_register('{\"a\":1}')", lambda: take(lib.srs_register(b'{"a":1}'))),
    ("srs_register('not json')", lambda: take(lib.srs_register(b"not json"))),
    ("srs_mint_t('','','')", lambda: take(lib.srs_mint_t(b"", b"", b""))),
    ("srs_mint_t('x','y','null')", lambda: take(lib.srs_mint_t(b"x", b"y", b"null"))),
    ("srs_mint_t(dx,'p','{}')", lambda: take(lib.srs_mint_t(b"abc", b"def", b"{}"))),
    ("srs_mint_so('','','','')", lambda: take(lib.srs_mint_so(b"", b"", b"", b""))),
    ("srs_requirements_token('null')", lambda: take(lib.srs_requirements_token(b"null"))),
    ("srs_requirements_token('{}')", lambda: take(lib.srs_requirements_token(b"{}"))),
]

for label, fn in CASES:
    try:
        out = fn()
    except Exception as exc:  # noqa: BLE001
        out = f"<python 异常: {exc}>"
    print(f"{label:<34} -> {str(out)[:220]}")
