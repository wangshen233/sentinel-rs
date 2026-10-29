# -*- coding: utf-8 -*-
"""Full register-write trace of the Python oracle.

Every `Vm.set()` call and every dispatched opcode is recorded, so the trace can
be compared line-by-line against the Rust VM's identical trace. This is the
primary divergence finder: the first differing line pinpoints the exact
register whose value diverged.

Format:
    <step>\top=<opcode>
    <step>\tset\t<reg>\t<jsstr(value)>
"""
import sys

import pyoracle
import sentinel_vm as svm

STEP = [0]
LINES = []
ON = [False]


def jsstr(v):
    return svm.jsstr(v)


def fmt_reg(k):
    try:
        return jsstr(k)
    except Exception:
        return repr(k)


def install():
    orig_set = svm.VM.set

    def set_(self, k, v):
        if ON[0]:
            LINES.append(f"{STEP[0]}\tset\t{fmt_reg(k)}\t{jsstr(v)}")
        return orig_set(self, k, v)

    svm.VM.set = set_

    orig_run = svm.VM.run_queue

    def run(self):
        while True:
            q = self.get(9)
            if not isinstance(q, list) or not q or self.done:
                break
            self.steps += 1
            STEP[0] = self.steps
            ins = q.pop(0)
            op = ins[0]
            fn = self.get(op)
            LINES.append(
                f"{self.steps}\top={jsstr(op)}\tins="
                + ",".join(jsstr(x) for x in ins[1:]))
            fn(*ins[1:])
        return self.get(16)

    svm.VM.run_queue = run
    return orig_run


def trace(path=None, device_id="x"):
    path = path or pyoracle.SAMPLE
    LINES.clear()
    ON[0] = False
    blob = pyoracle.load_challenge(path)
    vm = pyoracle.new_vm(device_id=device_id)
    vm.set(16, blob["p"])
    prog = svm.load_program(blob["challenge"]["turnstile"]["dx"], blob["p"])
    ON[0] = True
    vm.set(9, prog)
    vm.run_queue()
    ON[0] = False
    return vm, LINES


if __name__ == "__main__":
    install()
    vm, lines = trace()
    if len(sys.argv) > 1 and sys.argv[1] == "-":
        for ln in lines:
            print(ln)
    else:
        print(f"# steps={vm.steps} len={len(vm.out or '')} lines={len(lines)}")
