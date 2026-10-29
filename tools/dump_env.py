# -*- coding: utf-8 -*-
"""Export the Python oracle's fake environment (ctx.window) as JSON.

Everything the Rust VM needs to rebuild a byte-identical window is captured:

  * primitives are emitted verbatim (int stays int, float stays float)
  * arrays are JSON arrays (order preserved)
  * objects are {"$o": [[key, node], ...]} — serde_json maps sort keys, so the
    insertion order has to live in an ordered pair list
  * functions get {"$fn": "<access path>"} (e.g. "performance.now") plus
    {"$b": "<behaviour>"} — the canonical behaviour key Rust dispatches on
    (bound methods collapse onto their class function, e.g. "ElementStub.getContext")
  * a callable instance also carries its attributes: {"$o": [...], "$call": "Number"}
  * the root window is referenced as {"$self": true}
  * stub classes exposing a Python __getattr__ catch-all carry "$wild"

Usage:  python tools/dump_env.py [-o src/env_dump.json] [-v]
"""
import json
import math
import os
import sys
import types

import pyoracle

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
OUT = os.path.join(PROJ, "src", "env_dump.json")

_names_by_id = {}
_used_names = {}
_behaviours = {}
_collisions = []
_shared = []
SKIP_ATTR = ("vm",)


def fn_name(obj, path):
    oid = id(obj)
    if oid in _names_by_id:
        return _names_by_id[oid]
    name = path or getattr(obj, "__name__", "fn")
    prev = _used_names.get(name)
    if prev is not None and prev is not obj:
        n = 2
        while f"{name}#{n}" in _used_names:
            n += 1
        _collisions.append((name, f"{name}#{n}"))
        name = f"{name}#{n}"
    _used_names[name] = obj
    _names_by_id[oid] = name
    return name


def behaviour(obj, path):
    """Canonical name of the underlying behaviour (dedupes bound methods)."""
    target = getattr(obj, "__func__", obj)
    oid = id(target)
    if oid in _behaviours:
        return _behaviours[oid]
    if isinstance(target, type):
        name = target.__name__
    else:
        name = getattr(target, "__qualname__", "") or ""
        if name.startswith("<") or name == "":
            name = ""
        # lambdas / locals: fall back to the access path
        if not name or "<lambda>" in name or "<locals>" in name:
            name = path or getattr(target, "__name__", "fn")
        if "." in name and "<" in name:
            name = path
    _behaviours[oid] = name
    return name


def wild_kind(o):
    g = getattr(type(o), "__getattr__", None)
    if g is None:
        return None
    try:
        v = o.__getattr__("__probe__")
        return "wild_obj" if isinstance(v, dict) else "wild_none"
    except Exception:
        return "wild_none"


def own_names(o):
    names = [n for n in o.__dict__.keys() if not n.startswith("_") or n in ("_d", "_s")]
    for cls in type(o).__mro__:
        for name in vars(cls):
            if name.startswith("__") or name in names:
                continue
            names.append(name)
    return names


def enc(o, path, root, ancestors):
    if isinstance(o, float) and not math.isfinite(o):
        # JSON 没有 NaN/Infinity，标成 {"$num": ...}
        if math.isnan(o):
            return {"$num": "NaN"}
        return {"$num": "Infinity" if o > 0 else "-Infinity"}
    if o is None or isinstance(o, bool) or isinstance(o, (int, float, str)):
        return o
    if isinstance(o, types.ModuleType):
        if o.__name__ == "json":
            return {"$o": [[k, {"$fn": f"JSON.{k}", "$b": fn_name(v, f"JSON.{k}")}]
                           for k, v in (("dumps", o.dumps), ("loads", o.loads))]}
        return {"$o": []}
    if o is root:
        return {"$self": True}
    oid = id(o)
    if oid in ancestors:
        return {"$null": True}

    if isinstance(o, dict):
        anc = ancestors | {oid}
        return {"$k": "d",
                "$o": [[str(k), enc(v, f"{path}.{k}" if path else str(k), root, anc)]
                       for k, v in o.items()]}
    if isinstance(o, (list, tuple)):
        anc = ancestors | {oid}
        return [enc(v, f"{path}[{i}]", root, anc) for i, v in enumerate(o)]

    callable_obj = callable(o)
    is_inst = hasattr(o, "__dict__")
    if not callable_obj and not is_inst:
        return {"$o": []}

    if isinstance(o, (type, types.FunctionType, types.MethodType,
                      types.BuiltinFunctionType, types.BuiltinMethodType)):
        # 类 / 函数 / 绑定方法只作为可调用值导出：method 的 __dict__ 其实是
        # 底层函数的命名空间，当成对象属性导出会把它变成 "[object Object]"。
        return {"$fn": fn_name(o, path), "$b": behaviour(o, path)}

    anc = ancestors | {oid}
    node = {"$k": "p", "$o": []}
    if hasattr(o, "__dict__"):
        for name in own_names(o):
            if name in SKIP_ATTR:
                continue
            try:
                val = getattr(o, name)
            except Exception:
                continue
            node["$o"].append([name, enc(val, f"{path}.{name}" if path else name, root, anc)])
    if callable_obj:
        # 可调用实例（如 NumberStub）：既有属性又能被调用
        node["$fn"] = fn_name(o, path)
        node["$b"] = behaviour(o, path)
    else:
        w = wild_kind(o)
        if w:
            node["$wild"] = w
    return node


def build(profile=None, device_id="x"):
    vm = pyoracle.new_vm(profile=profile, device_id=device_id)
    root = vm.window
    node = {"$o": [[str(k), enc(v, str(k), root, frozenset({id(root)}))]
                   for k, v in root.items()]}
    return node


def main(argv):
    out = OUT
    if "-o" in argv:
        out = argv[argv.index("-o") + 1]
    node = build()
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(node, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    print("wrote", out, os.path.getsize(out), "bytes")
    print("paths:", len(_used_names), "behaviours:", len(_behaviours))
    if _collisions:
        print("name collisions (renamed):")
        for a, b in _collisions:
            print("   ", a, "->", b)
    if _shared:
        print("shared refs:")
        for a, b in _shared:
            print("   ", a, "->", b)
    if "-v" in argv:
        for n in sorted(_behaviours.values()):
            print("behaviour:", n)


if __name__ == "__main__":
    main(sys.argv[1:])
