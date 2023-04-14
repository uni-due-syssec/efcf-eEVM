import sys
import json
import math

with open(sys.argv[1]) as f:
    state = json.load(f)


def int2dictbytes(i):
    if not isinstance(i, int):
        i = int(i, 0)
    length = math.ceil(i.bit_length() / 8.0)
    ibytes = i.to_bytes(byteorder='big', length=length)
    bstr = "".join(f"\\x{v:02X}" for v in ibytes)

    return "\"" + bstr + "\""


def interesting_val(i):
    if i < 256:
        return False

    return any(b != 0 or b != 1 or b != 0xff
               for b in i.to_bytes(32, byteorder='big'))


for account in state['accounts']:
    addr = account[0].strip()
    print(int2dictbytes(int(addr, 16)))

    for k, v in account[1][1].items():
        k = int(k, 16)
        v = int(v, 16)

        if interesting_val(k):
            print(int2dictbytes(k))

        if interesting_val(v):
            print(int2dictbytes(v))
