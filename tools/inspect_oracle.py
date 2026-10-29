# -*- coding: utf-8 -*-
"""Introspection helpers around the deterministic oracle."""
import sys
import collections

import pyoracle
import sentinel_vm as svm


def plain_t(vm):
    import base64
    if not vm.out:
        return None
    return base64.b64decode(vm.out).decode("latin-1")


def report(show=40):
    vm = pyoracle.run()
    print("steps =", vm.steps, "len =", len(vm.out or ""), "err =", vm.err)
    txt = plain_t(vm)
    if txt:
        print("plain len =", len(txt))
        print("plain head =", txt[:200].encode("unicode_escape").decode())
    print("\n-- window/doc/nav misses (index returned UNDEF) --")
    for m in sorted(vm.misses):
        print("   miss:", m)
    print("\n-- reads by label --")
    per = collections.Counter((lbl, key) for lbl, key, _ in vm.reads)
    for (lbl, key), n in sorted(per.items()):
        print(f"   {lbl}.{key} x{n}")
    return vm


if __name__ == "__main__":
    report()
