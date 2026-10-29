# -*- coding: utf-8 -*-
"""Deterministic Python oracle harness for sentinel_vm.py.

The upstream Python VM is non-deterministic in four places:
  * Math.random()                  -> random.random()
  * crypto.getRandomValues()       -> os.urandom()
  * crypto.randomUUID()            -> uuid.uuid4()
  * Date.now() / performance.now() -> time.time() / time.perf_counter()
  * window.__oai_so_*              -> random.randint()

We pin all of them *before* the environment is constructed so the same
challenge always yields the same `t`. Every pin is mirrored verbatim on the
Rust side (src/env.rs constants / src/vm.rs dispatch).

Pins (must stay in sync with src/env.rs):
    Date.now()        = 1700000000000
    performance.now() = 15.5
    Math.random()     = 0.5
    randint(a, b)     = a          (so __oai_so_* take their lower bound)
    urandom(n)        = b"\\x00" * n
    uuid4()           = 00000000-0000-4000-8000-000000000000
"""
import os
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
ORACLE_DIR = os.environ.get("SENTINEL_ORACLE_DIR") or os.environ.get("SENTINEL_PY_DIR")
if not ORACLE_DIR:
    sys.exit(
        "需要设置 SENTINEL_ORACLE_DIR（或 SENTINEL_PY_DIR）指向 Python oracle 目录"
        "（含 sentinel_vm.py 的那个目录）"
    )
SAMPLE = os.path.join(PROJ, "sample_challenge.json")

FIXED_NOW_MS = int(os.environ.get("SENTINEL_PIN_CLOCK_MS", 1700000000000))
FIXED_PERF_NOW = float(os.environ.get("SENTINEL_PIN_PERF_NOW", 15.5))
FIXED_RANDOM = float(os.environ.get("SENTINEL_PIN_RANDOM", 0.5))
FIXED_UUID = "00000000-0000-4000-8000-000000000000"

if ORACLE_DIR not in sys.path:
    sys.path.insert(0, ORACLE_DIR)

import sentinel_vm  # noqa: E402

_PATCHED = False


def patch(vm_mod=sentinel_vm):
    """Pin every nondeterministic source *inside* the oracle module."""
    global _PATCHED
    if _PATCHED:
        return vm_mod
    import random as _random
    import time as _time

    _random.random = lambda: FIXED_RANDOM
    _random.randint = lambda a, b: a
    _random.randrange = lambda *a, **k: (a[0] if a else 0)

    _time.time = lambda: FIXED_NOW_MS / 1000.0
    _time.perf_counter = lambda: 0.0

    os.urandom = lambda n: bytes(n)
    uuid.uuid4 = lambda: FIXED_UUID

    # performance.now() and timeOrigin must be constant regardless of perf_counter.
    vm_mod.PerfStub.now = lambda self: FIXED_PERF_NOW
    vm_mod.PerfStub.timeOrigin = property(lambda self: int(FIXED_NOW_MS - FIXED_PERF_NOW))

    _PATCHED = True
    return vm_mod


def load_challenge(path=SAMPLE):
    import json
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def new_vm(profile=None, device_id="x"):
    patch()
    return sentinel_vm.VM(profile=profile or {}, device_id=device_id)


def run(path=SAMPLE, device_id="x", profile=None):
    """Run the dx program exactly like the accept command does."""
    blob = load_challenge(path)
    vm = new_vm(profile=profile, device_id=device_id)
    vm.set(16, blob["p"])
    vm.set(9, sentinel_vm.load_program(blob["challenge"]["turnstile"]["dx"], blob["p"]))
    vm.run_queue()
    return vm


if __name__ == "__main__":
    c = run()
    print("steps", c.steps, "len", len(c.out or ""))
    print("err", c.err)
    print("t", (c.out or "")[:120])
