# -*- coding: utf-8 -*-
"""Peek at a subtree of src/env_dump.json: python tools/peek.py Reflect Math ..."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
PATH = os.path.join(PROJ, "src", "env_dump.json")


def main():
    d = json.load(open(PATH, encoding="utf-8"))
    root = dict((k, v) for k, v in d["$o"])
    for name in sys.argv[1:]:
        print("=== " + name)
        print(json.dumps(root.get(name), indent=1, ensure_ascii=False)[: int(os.environ.get("PEEK_MAX", "1200"))])


if __name__ == "__main__":
    main()
