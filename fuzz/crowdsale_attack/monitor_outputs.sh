#!/usr/bin/env bash
rm *.output
for x in ../m*/{crashes,queue}/id* ../s*/{crashes,queue}/id* ../default/{crashes,queue}/id*; do 
    env DEBUG_PRINT=1 ../../build_afuzz/fuzz_multitx $x 2>/dev/null > $(basename $x).output;
done
../../fuzz/crowdsale_attack/analyze-txid.py
