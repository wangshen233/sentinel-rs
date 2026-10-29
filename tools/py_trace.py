# -*- coding: utf-8 -*-
"""Step-level trace of the Python oracle, for diffing against the Rust VM.

Trace line format (tab separated):

    step  op  ins...  |  changed-registers

`changed-registers` lists `reg=value` for every register that the handler
wrote, rendered with the VM's own jsstr() so both sides agree on formatting.
The Rust side writes the identical format (see `Vm::trace`), so a plain diff
pinpoints the first divergent step.
"""
import sys

import pyoracle
import sentinel_vm as svm

WRITE_OPS = {1: (0,), 2: (0,), 5: (0,), 6: (0,), 8: (0,), 12: (0,), 14: (0,),
             15: (0,), 18: (0,), 19: (0,), 24: (0,), 29: (0,), 30: (0,),
             33: (0,), 34: (0,), 35: (0,), 11: (0,), 13: (0,), 17: (0,),
             3: (0,), 4: (0,), 0: (0,), 20: (0,), 21: (0,), 23: (0,), 7: (0,)}


def jsstr(v):
    return svm.jsstr(v)


def run_trace(limit=None, show=None):
    blob = pyoracle.load_challenge()
    vm = pyoracle.new_vm()

    lines = []
    orig = svm.VM.run_queue

    def traced(self):
        while True:
            q = self.get(9)
            if not isinstance(q, list) or not q or self.done:
                break
            self.steps += 1
            ins = q.pop(0)
            op = ins[0]
            fn = self.get(op)
            before = {a: jsstr(self.get(a)) for a in ins[1:] if isinstance(a, int)}
            try:
                fn(*ins[1:])
            except Exception as exc:
                lines.append(f"{self.steps}\top={op}\tERROR {type(exc).__name__}: {exc}\tins={ins[1:]}")
                raise
            after = []
            for a in ins[1:]:
                if isinstance(a, int):
                    va = self.get(a)
                    if jsstr(va) != before[a]:
                        after.append(f"{a}={jsstr(va)}")
            lines.append(f"{self.steps}\top={op}\t" + "\t".join(after))
        return self.get(16)

    svm.VM.run_queue = traced
    try:
        vm.set(16, blob["p"])
        vm.set(9, svm.load_program(blob["challenge"]["turnstile"]["dx"], blob["p"]))
        vm.run_queue()
    finally:
        svm.VM.run_queue = orig
    return vm, lines


if __name__ == "__main__":
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 10 ** 9
    vm, lines = run_trace()
    for ln in lines[lo - 1:hi]:
        print(ln)
    print("# steps", vm.steps, "len", len(vm.out or ""), file=sys.stderr)
