#!/usr/bin/env python
"""
Quickly grep for u256 constants in the code and convert them to a dictionary
consumable by a fuzzer.

Modern fuzzer automatically scan for such constants during LTO or startup.
However, sometimes this doesn't work, or the larger constants are not picked up
by passes searching for constants |> 64 bit|. This way we generate these tokens
explicitly.
"""

import sys
import subprocess as sp
import string

out = sp.check_output("grep -ihorEIs '(0x[a-f0-9]+|[0-9]+)_u256' | sort -u",
                      shell=True)

if out:
    integers = set()
    for x in map(lambda y: y.strip()[:-5], out.split(b"\n")):
        if not x:
            continue
        try:
            i = int(x, 0)
            integers.add(i)
        except ValueError as e:
            print("warning failed to convert", repr(x), "to integer:", e, file=sys.stderr)
    for i in sorted(integers):
        _b = i.to_bytes(i.bit_length() // 8 + 1, "big")
        # both little and big endian repr to dictionary
        for b in set((_b, _b[::-1])):
            sb = "".join(f"\\x{val:02X}" for val in b)
            print('"' + sb + '"')
else:
    print("error no output", file=sys.stderr)
    sys.exit(1)
