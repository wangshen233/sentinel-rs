# -*- coding: utf-8 -*-
"""Small viewer for src/env_dump.json (structure sanity check)."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
PATH = os.path.join(PROJ, "src", "env_dump.json")


def label(node):
    if isinstance(node, dict):
        if "$fn" in node:
            return f"fn:{node['$b']}"
        if "$self" in node:
            return "self"
        if "$wild" in node:
            return f"wild:{node['$wild']}"
        if "$o" in node:
            return "obj(" + ",".join(k for k, _ in node["$o"]) + ")"
        return "?"
    if isinstance(node, list):
        return f"arr[{len(node)}]"
    return repr(node)


def main():
    d = json.load(open(PATH, encoding="utf-8"))
    root = dict((k, v) for k, v in d["$o"])
    print("window keys (%d):" % len(root))
    for k, v in d["$o"]:
        print(f"  {k:28s} {label(v)[:110]}")
    for name in sys.argv[1:]:
        node = root.get(name)
        print("\n=== " + name)
        if isinstance(node, dict) and "$o" in node:
            for k, v in node["$o"]:
                print(f"  {k:28s} {label(v)[:110]}")


if __name__ == "__main__":
    main()
