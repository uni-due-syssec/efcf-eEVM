#!/usr/bin/env python

import sys
import glob
from pprint import pprint

files = [x.read() for x in map(open, glob.glob("*.output"))]

if not files:
    print(
        "Warning: no .output files in current working dir",
        "",
        "solution: run something like this",
        "    for x in ../m0/queue/id*; do env DEBUG_PRINT=1 ../../build_afuzz/fuzz_multitx $x 2>/dev/null > $(basename $x).output; done",
        "",
        sep='\n',
        file=sys.stderr)
    sys.exit(1)

txsigs = [[
    line.replace("4byte sig: ", "").lower().strip()
    for line in data.split("\n") if "sig" in line
] for data in files]

# crowdsale valids
valids = {
    "0x5fcf9fce": "echidna_alwaystrue()",
    "0xe8b5e51f": "invest()",
    "0x590e1ae3": "refund()",
    "0x13af4035": "setOwner(address)",
    "0x2cc82655": "setPhase(uint256)",
    "0x3ccfd60b": "withdraw()",
}
# TX deps: invest -> setPhase -> (withdraw|refund)
# setOwner can be called anytime before withdraw
attack_sequences = [
    ('0xe8b5e51f', '0x2cc82655', '0x13af4035', '0x3ccfd60b'),
    ('0xe8b5e51f', '0x13af4035', '0x2cc82655', '0x3ccfd60b'),
    ('0x13af4035', '0xe8b5e51f', '0x2cc82655', '0x3ccfd60b'),
]

txtypes = set()
unique_sigs = set()
unique_txs = set(map(tuple, txsigs))

# we filter out repeated tx sigs

for txs in txsigs:
    p = []

    for t in txs:
        unique_sigs.add(t)

        if not p or p[-1] != t:
            p.append(t)
    txtypes.add(tuple(p))

# pprint(txtypes)

txtypes_filtered = set(
    map(lambda x: tuple(y if y in valids else None for y in x), txtypes))
# pprint(txtypes_filtered)

txtypes_valid_only = set(
    map(lambda x: tuple(filter(None, (y if y in valids else None for y in x))),
        txtypes))
# pprint(txtypes_valid_only)


def to_named(seq):
    return tuple(valids[x] if x in valids else None for x in seq)


for x in txtypes_filtered:
    print("  ", *(to_named(x)))
print()
print("uinque tx sig combinations:", len(unique_txs))
print("uinque tx sig combinations without repetitions:", len(txtypes))
print("unique_sigs", len(unique_sigs), "found valids: ",
      sum(1 for x in valids if x in unique_sigs), "/", len(valids))

for attk in attack_sequences:
    if attk in txtypes_filtered:
        print("found exact attack sequence:", to_named(attk))

    if attk in txtypes_valid_only:
        print("found exact attack sequence (in valids only):", to_named(attk))

    attack_found = None
    longest_seq = 0

    for seq in unique_txs:
        attack_found = seq

        for i, (tx, txn) in enumerate(zip(attk[:-1], attk[1:])):
            if tx in seq and txn in seq:
                tx_pos = seq.index(tx)

                if any(i for i, v in enumerate(seq) if v == txn and i > tx_pos):
                    longest_seq = max(longest_seq, i + 1)

                    continue

            attack_found = None

            break

        if attack_found:
            print("found potential attack sequence:", to_named(attack_found))

    print("longest attack sequence: ", longest_seq, "/", len(attk))
