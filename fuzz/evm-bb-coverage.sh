#!/usr/bin/env bash
set -e -o pipefail
if [[ -z "$1" ]]; then
    echo "usage: $0 ./path/to/fuzz_out/"
    exit 1
fi

dbg=0
config=""

set -u

cd "$1" || (echo "Failed to cd into \"$1\"" && false)

if [[ -e "./fuzz-config.sh" ]]; then
    config="$(cat ./fuzz-config.sh)"
    config="${config/$'\n'/}"  # remove newlines
fi

for afl in ./*; do
    [[ -d "$afl/queue/" ]] || continue
    pushd "$afl" >/dev/null || (echo "Failed to cd into \"$afl\"" && false)

    mkdir ./outputs/ || true
    for x in ./{queue,crashes}/*; do
        if [[ "$x" == *README* ]]; then
            continue
        fi
        #echo "$x"
        base="$(basename "$x")"
        EVM_COVERAGE_FILE="$(realpath -m "./outputs/$base.evmcov")"
        # write coverage to file; but allow crashes here (|| true)
        env $config EVM_NO_ABORT=1 EVM_DEBUG_PRINT=$dbg EVM_COVERAGE_FILE="$EVM_COVERAGE_FILE" \
            ../build/fuzz_multitx "$x" \
            > "./outputs/$base.out" 2>&1 || true

        touch "$EVM_COVERAGE_FILE"
        # the cov traces can become quite large; but we are only interested in the BB
        # coverage; so we can ignore duplicated trace entries and save some bytes
        sort -u < "$EVM_COVERAGE_FILE" > "$EVM_COVERAGE_FILE.u"
        rm "$EVM_COVERAGE_FILE"
        mv "$EVM_COVERAGE_FILE.u" "$EVM_COVERAGE_FILE"
    done

    popd >/dev/null
done


dir=seeds_outputs
mkdir "./$dir" || true
for x in ./seeds/*; do
    #echo "$x"
    base="$(basename "$x")"
    EVM_COVERAGE_FILE="$(realpath -m "./$dir/$base.evmcov")"
    # write coverage to file; but allow crashes here (|| true)
    env $config EVM_NO_ABORT=1 DEBUG_PRINT=$dbg EVM_COVERAGE_FILE="$EVM_COVERAGE_FILE" \
        ./build/fuzz_multitx "$x" > "./$dir/$base.out" 2>&1 || true

    touch "$EVM_COVERAGE_FILE"
    sort -u < "$EVM_COVERAGE_FILE" > "$EVM_COVERAGE_FILE.u"
    rm "$EVM_COVERAGE_FILE"
    mv "$EVM_COVERAGE_FILE.u" "$EVM_COVERAGE_FILE"
done

find ./*/outputs/ ./seeds_outputs/ -name "*.evmcov" -exec cat \{\} \; | sort -u > ./all.evmcov
find ./seeds_outputs/ -name "*.evmcov" -exec cat \{\} \; | sort -u > ./seeds.evmcov

CONTRACT_BB=""
if test -e ./contract.bb_list; then
    CONTRACT_BB=./contract.bb_list
else
    try_path="../../../contracts/$(basename "$(realpath -P "./contract.abi")" | cut -f 1 -d '.').bb_list"
    try_path="$(realpath "$try_path")"
    if test -e "$try_path"; then
        CONTRACT_BB="$try_path"
    fi
fi

if [[ -e "$CONTRACT_BB" ]]; then
    for cov in seeds.evmcov all.evmcov; do
        test -e "./$cov" || continue
        python > "./coverage-percent-$cov" <<EOF
import sys
with open("$CONTRACT_BB") as f:
    base = set(map(lambda x: int(x.strip(), 0), filter(lambda l: l.strip(), f.readlines())))
with open("./$cov") as f:
    run = set(map(lambda x: int(x.strip(), 0), filter(lambda l: l.strip(), f.readlines())))
if not run.issubset(base):
    diff = run.difference(base)
    #print(f"run contains unknown / non-bb addresses {diff}... fixing up", file=sys.stderr)
    run = run - diff
#print("uncovered BBs:", base.difference(run), file=sys.stderr)
print(len(run) / (len(base) / 100.0))
EOF
        echo "$cov BB-Coverage Percent: $(cat  "./coverage-percent-$cov")"
    done
fi
