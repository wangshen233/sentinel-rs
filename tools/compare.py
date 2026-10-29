# -*- coding: utf-8 -*-
"""Compare the Rust VM against the Python oracle.

    python tools/compare.py            # steps + t byte comparison
    python tools/compare.py --trace    # also diff the step/register trace

The Rust side is `src/bin/sentinel-trace.rs` (same code path as the shipped
`sentinel-rs` binary, plus a full `t` dump and an optional write trace), so the
comparison covers exactly what `sentinel-rs.exe sample_challenge.json` prints.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)

import pyoracle  # noqa: E402

EXE = os.path.join(PROJ, "target", "release", "sentinel-trace.exe")
EXE_ALT = os.path.join(PROJ, "target", "release", "sentinel-trace")


def rust_bin():
    for cand in (EXE, EXE_ALT):
        if os.path.exists(cand):
            return cand
    return None


def run_python(path=None):
    vm = pyoracle.run(path or pyoracle.SAMPLE)
    return vm.steps, vm.out or "", vm.err


def run_rust(path=None, trace_file=None):
    exe = rust_bin()
    if exe is None:
        return None, "rust binary missing (cargo build --release --bin sentinel-trace)", None
    env = dict(os.environ)
    if trace_file:
        env["SENTINEL_TRACE_FILE"] = trace_file
    proc = subprocess.run(
        [exe, path or pyoracle.SAMPLE],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    lines = (proc.stdout or "").splitlines()
    steps = t = err = None
    for line in lines:
        if line.startswith("steps="):
            steps = int(line.split("=", 1)[1])
        elif line.startswith("t="):
            t = line.split("=", 1)[1]
        elif line.startswith("err=") or line.startswith("err_field="):
            err = line.split("=", 1)[1]
    return steps, t, err


def first_diff(a, b):
    limit = min(len(a), len(b))
    for i in range(limit):
        if a[i] != b[i]:
            return i
    if len(a) != len(b):
        return limit
    return -1


def show_diff(py_t, rs_t):
    idx = first_diff(py_t, rs_t)
    if idx < 0:
        return
    lo = max(0, idx - 40)
    print(f"  first diff at char {idx}")
    print(f"  py[{lo}:{idx+40}] = {py_t[lo:idx+40]!r}")
    print(f"  rs[{lo}:{idx+40}] = {rs_t[lo:idx+40]!r}")


def diff_traces(py_file, rs_file, context=12):
    py_lines = open(py_file, encoding="utf-8", errors="replace").read().splitlines()
    rs_lines = open(rs_file, encoding="utf-8", errors="replace").read().splitlines()
    limit = min(len(py_lines), len(rs_lines))
    for i in range(limit):
        if py_lines[i] != rs_lines[i]:
            print(f"  trace diverges at line {i + 1} (of {len(py_lines)} py / {len(rs_lines)} rs)")
            for j in range(max(0, i - 6), min(len(py_lines), i + 3)):
                p = py_lines[j][:200]
                r = rs_lines[j][:200] if j < len(rs_lines) else "<missing>"
                mark = "  " if p == r else ">>"
                print(f"  {mark} py[{j+1}] {p}")
                print(f"     rs[{j+1}] {r}")
            return i + 1
    if len(py_lines) != len(rs_lines):
        print(f"  trace length differs: py={len(py_lines)} rs={len(rs_lines)}")
        return limit + 1
    print("  trace identical")
    return None


def main(argv):
    want_trace = "--trace" in argv
    py_steps, py_t, py_err = run_python()
    rs_trace = os.path.join(PROJ, "target", "rs_writes.txt")
    rs_steps, rs_t, rs_err = run_rust(trace_file=rs_trace if want_trace else None)

    print(f"python: steps={py_steps} tlen={len(py_t)} err={py_err}")
    print(f"rust  : steps={rs_steps} tlen={len(rs_t or '')} err={rs_err}")
    ok_steps = py_steps == rs_steps
    ok_t = py_t == (rs_t or "")
    print(f"steps_equal={ok_steps} equal={ok_t}")
    if ok_t:
        print(f"t = {py_t}")
    else:
        show_diff(py_t, rs_t or "")

    if want_trace:
        import py_writes

        py_writes.install()
        _, py_lines = py_writes.trace()
        py_file = os.path.join(PROJ, "target", "py_writes.txt")
        with open(py_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(py_lines) + "\n")
        diff_traces(py_file, rs_trace)

    return 0 if (ok_steps and ok_t) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
