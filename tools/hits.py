# -*- coding: utf-8 -*-
"""Record every property read the dx program performs on the fake environment."""
import collections
import sys

import pyoracle
import sentinel_vm as svm

HITS = []


def install_probe():
    orig = svm.VM.index

    def index(self, o, k):
        try:
            key = svm.jsstr(k)
        except Exception:
            key = repr(k)
        label = self._labels.get(id(o))
        v = orig(self, o, k)
        tn = type(o).__name__
        HITS.append((label or "", tn, key, type(v).__name__, svm.jsstr(v)[:60]))
        return v

    svm.VM.index = index


def main():
    install_probe()
    vm = pyoracle.run()
    print("steps", vm.steps, "len", len(vm.out or ""), "err", vm.err)
    per = collections.Counter((tn, key) for _, tn, key, _, _ in HITS)
    for (tn, key), n in sorted(per.items()):
        vals = {v for (_, t2, k2, _, v) in HITS if t2 == tn and k2 == key}
        print(f"{tn}.{key}\tx{n}\tvals={sorted(vals)[:6]}")
    print("\n-- undefined results --")
    for (_, tn, key, vt, v) in HITS:
        if vt == "Undef" or v == "undefined":
            print(f"  UNDEF {tn}.{key}")


if __name__ == "__main__":
    main()
