#!/usr/bin/env python3

import os
import glob
import sys
import re

tc = sys.argv[1]
assert os.path.exists(tc), "arg doesn't exist"

SRC_RE = re.compile("src:([0-9]+)(\+[0-9]+)?,")

worklist = [tc]
d = os.path.dirname(tc)
queue_path = "./" + os.path.relpath(os.path.join(d, "..", "queue"))

while worklist:
    item = worklist.pop()
    print(item)
    b = os.path.basename(item)

    m = SRC_RE.search(b)
    if m and m.groups():
        src = m.groups()[0]
        src_start = f"id:{src}"
        # print(src_start, file=sys.stderr)
        for fpath in os.listdir(queue_path):
            if fpath.startswith(src_start):
                worklist.append(os.path.join(queue_path, fpath))
                break
    elif "orig" in b:
        pass
    else:
        print("failed to identify source in", b, file=sys.stderr)
