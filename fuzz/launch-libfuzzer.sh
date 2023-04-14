#!/usr/bin/env bash
set -e -o pipefail

SUDO=""
if command -v sudo; then
    SUDO=sudo
fi

if [[ -z "$FUZZ_USE_SHM" ]]; then
    FUZZ_USE_SHM=1
fi
if [[ -z "$FUZZ_USE_TMPFS" ]]; then
    if [[ "$FUZZ_USE_SHM" -eq 0 ]]; then
        FUZZ_USE_TMPFS=1
    else
        FUZZ_USE_TMPFS=0
    fi
fi
if [[ -z "$MUT_TYPE" ]]; then
    MUT_TYPE=release
fi
if [[ -z "$MEMORY_LIMIT" ]]; then
    MEMORY_LIMIT="500"
fi

if [[ -z "$FUZZ_LAUNCHER_DONT_REBUILD" ]]; then
    FUZZ_LAUNCHER_DONT_REBUILD=0
fi

if [[ -z "$FUZZ_POWER_SCHED" ]]; then
    FUZZ_POWER_SCHED="fast"
fi

if [[ -z "$MUTATOR_PATH" ]]; then
    MUTATOR_PATH=""
fi

set -u

echo "$# args: $*"

echo "[libfuzzer] sanity check"
test -e ./contracts && test -e ./fuzz && test -e ./fuzz/abi
SOURCE_DIR="$(pwd)"
echo "[libfuzzer] good - running in SOURCE_DIR=$SOURCE_DIR"


if ! env | grep FUZZ_CORES >/dev/null; then
    export FUZZ_CORES=1
fi

echo "[libfuzzer] utilizing $FUZZ_CORES cores"

# 4 hours fuzzing time per contract
if ! env | grep FUZZING_TIME >/dev/null; then
    FUZZING_TIME="$(python -c "print(4 * 60 * 60)")"
    export FUZZING_TIME
fi
if (( $# >= 2 )); then
    if [[ -n "$2" ]]; then
        FUZZING_TIME="$2"
    fi
fi
POSTFIX=""
if (( $# >= 3 )); then
    POSTFIX="$3"
fi
echo "[libfuzzer] fuzzing time is $FUZZING_TIME"

if [[ -z "$MUTATOR_PATH" ]]; then
    MUTATOR_PATH=""
    for try_path in "../ethmutator" "../../ethmutator" "../../ethmutator.git" "/src/ethmutator"; do
        if test -e "$try_path/Cargo.toml"; then
            MUTATOR_PATH="$try_path"
            break
        fi
    done
fi
if [[ -n "$MUTATOR_PATH" ]]; then
    MUTATOR_PATH="$(realpath "$MUTATOR_PATH")"
fi
export MUTATOR_PATH


TARGET_CONTRACT="$1"

DICT_PATH="$(realpath -m ./fuzz/dict/$TARGET_CONTRACT.dict)"
test -e "$DICT_PATH" || echo "need dictionary file at $DICT_PATH for this experiment"

ABI_PATH="$(realpath -m ./fuzz/abi/$TARGET_CONTRACT.abi)"
if ! test -e "$ABI_PATH"; then
    echo "no ABI file at $ABI_PATH - not using ABI for this experiment"
    ABI_PATH=""
fi

BBLIST_PATH="$(realpath ./contracts/${TARGET_CONTRACT}.bb_list)"

GENERIC_SEEDS="$(realpath -m ./fuzz/generic_seeds)"

EVM_PROPERTY_PATH="${SOURCE_DIR}/fuzz/properties/${TARGET_CONTRACT}.signatures"
if test -e "$EVM_PROPERTY_PATH"; then
    export EVM_PROPERTY_PATH
    echo "[PROPERTY]  ENABLED - Checking the properties listed in \"${EVM_PROPERTY_PATH}\"!"
else 
    EVM_PROPERTY_PATH=""
    #echo "[PROPERTY] DISABLED"
fi

mkdir -p ./fuzz/out || true
FUZZ_CWD="$(realpath -ms "./fuzz/out/${TARGET_CONTRACT}_$(basename "$0" | cut -f 1 -d '.')_$POSTFIX")"

BUILD_DIR="$(realpath -m "./fuzz/build/libfuzzer/$TARGET_CONTRACT")"

if ! env | grep FUZZ_EXEC_TIMEOUT >/dev/null; then
    FUZZ_EXEC_TIMEOUT="-t 50"
fi

# it seems CMPLOG builds sometimes need quite a big map size? default is 2**16;
# but we switch to 2**18 - should work for quite some contracts, no?
AFL_MAP_SIZE="$(python -c "print(2**18)")"
export AFL_MAP_SIZE

cat - <<EOF
TARGET_CONTRACT=$1
FUZZING_TIME=$FUZZING_TIME
SOURCE_DIR=$SOURCE_DIR
DICT_PATH=$DICT_PATH
ABI_PATH=$ABI_PATH
FUZZ_CWD=$FUZZ_CWD
BUILD_DIR=$BUILD_DIR
FUZZ_CORES=$FUZZ_CORES
EOF

if test -d "$FUZZ_CWD"; then
    $SUDO umount "$FUZZ_CWD" || true
    rm -rf "$FUZZ_CWD"/ || true
fi
if test -L "$FUZZ_CWD"; then
    rm -rf "$FUZZ_CWD"/* || true
    rm "$FUZZ_CWD" || true
fi
RAMDISK_DIR=""
if [[ "$FUZZ_USE_SHM" -eq 1 ]] && [[ -d /dev/shm ]]; then
    rm -rf "$FUZZ_CWD" || true
    RAMDISK_DIR="/dev/shm/efcf/$(basename "$FUZZ_CWD")"
    rm -rf "$RAMDISK_DIR" || true
    mkdir -p "$RAMDISK_DIR"
    ln -s "$RAMDISK_DIR" "$FUZZ_CWD"
else
    mkdir -p "$FUZZ_CWD" || true
    if [[ "$FUZZ_USE_TMPFS" -eq 1 ]]; then
        $SUDO mount -t tmpfs - "$FUZZ_CWD" || true
    fi
fi
pushd "$FUZZ_CWD"
rm -r corpus || true
popd

set -x
if test -e "$BUILD_DIR"; then
    pushd "$BUILD_DIR"; ninja fuzz_multitx; popd
else
    ./quick-build.sh libfuzzer "$TARGET_CONTRACT"
fi


pushd "$FUZZ_CWD"

ln -s "$DICT_PATH" "dict"
ln -s "$ABI_PATH" "contract.abi" || true
ln -s "$BBLIST_PATH" "contract.bb_list"
ln -s "$BUILD_DIR" "build"

rm -rf corpus || true
mkdir -p corpus || true
printf "\x00" > corpus/nullbyte
if test -d "$GENERIC_SEEDS"; then
    cp "$GENERIC_SEEDS"/*.bin ./corpus/ || true
fi


# create some shortcut analysis scripts
cat > r.sh <<EOF
#!/usr/bin/bash
set -eu
export EVM_DEBUG_PRINT=1
if test -e ./build/fuzz_multitx; then
    ./build/fuzz_multitx \$1
else
    ./fuzz_multitx \$1
fi
echo
if test -e ./contract.abi; then
    efuzzcaseanalyzer -a ./contract.abi \$1
else
    efuzzcaseanalyzer \$1
fi
EOF
cat > a.sh <<EOF
#!/usr/bin/bash
set -eu
if test -e ./contract.abi; then
    efuzzcaseanalyzer -a ./contract.abi \$@
else
    efuzzcaseanalyzer \$@
fi
EOF
cat > m.sh <<EOF
#!/usr/bin/bash
set -eu
if test -e ./contract.abi; then
    efuzzcaseminimizer -a ./contract.abi \$@
else
    efuzzcaseminimizer \$@
fi
EOF
chmod +x a.sh r.sh m.sh

echo "==========================================================="
echo "testing harness binary with empty seed input:"
env EVM_DEBUG_PRINT=1 EVM_DUMP_STATE="./state" ./build/fuzz_multitx corpus/nullbyte
echo "==========================================================="

if [[ -z "$MUTATOR_PATH" ]]; then
    ANALYZER="$(command -v efuzzcaseanalyzer)"
    MINIMIZER="$(command -v efuzzcaseminimizer)"
else
    pushd "$MUTATOR_PATH"
    MUT_TYPE=release
    env CC=clang CXX=clang++ RUSTFLAGS="-A warnings" cargo build -q "--$MUT_TYPE" || true
    ANALYZER="$(realpath "$(pwd)/target/$MUT_TYPE/efuzzcaseanalyzer")"
    MINIMIZER="$(realpath "$(pwd)/target/$MUT_TYPE/efuzzcaseminimizer")"
    popd
fi

pwd
trap "test -e '$PWD/end' || date > '$PWD/end'" EXIT

if [[ -n "$ABI_PATH" ]]; then 
    ABI_PARAM="CONTRACT_ABI=$ABI_PATH"
else
    ABI_PARAM=""
fi
# TODO: currently not supported env params
#env CONTRACT_DICT="$DICT_PATH" \
#    $ABI_PARAM \

# make sure there are no stale processes around
pkill -KILL fuzz_multitx || true

mkdir -p findings || true

date > "start"
/usr/bin/time -v -o ./fuzz.time \
        env \
            EVM_CREATE_TX_INPUT="${EVM_CREATE_TX_INPUT:-""}" \
            "$BUILD_DIR/fuzz_multitx" \
            -use_value_profile=1 \
            -entropic=1 \
            -max_len=8192 \
            -dict="$DICT_PATH" \
            -jobs="$FUZZ_CORES" \
            -artifact_prefix="./findings/" \
            ./corpus \
        2>&1 | tee "libfuzzer.log"
date > "end"

echo "[+] computing EVM-block coverage"
"$SOURCE_DIR"/fuzz/evm-bb-coverage.sh ./

rm queue_tx_summary crashes_tx_summary || true


BUGS="$(realpath "./bugs")"
BUGTYPES="$(realpath "./bugtypes")"
touch "$BUGTYPES"
touch "$BUGS"
echo "[+] minimizing crashes"
crash_dir=./findings/

echo "|-> analyzing dir $crash_dir"
mkdir -p "$crash_dir/../crashes_min_out/"
if [[ -n "$(ls -A $crash_dir/../crashes_min/)" ]]; then
    for f in "$crash_dir/../crashes_min/"*; do
        echo "processing crash $f"
        test -e "$f"

        abi_path="$(realpath ./contract.abi)"
        bin_path="$(realpath ./build/fuzz_multitx)"
        c="$(realpath "$crash_dir/../crashes_min_out/$(basename "$f")")"
        if "$MINIMIZER" --overwrite --abi "$abi_path" \
            "$bin_path" "$f" >"$c.min.log" 2>&1;
        then
            echo "minimizer succeeded on $f!"
            #env EVM_DEBUG_PRINT=1 EVM_ALLOW_INDIRECT_ETHER_TRANSFERS=1 \
            #    "$bin_path" "$c" \
            #    >"$c.indirect-transfers-allowed.out" 2>&1 || true
        else
            echo "minimizer failed on $f!"
            cat "$c.min.log" || true
        fi
        env EVM_DEBUG_PRINT=1 EVM_DUMP_STATE="$c.state" \
            "$bin_path" "$f" >"$c.out" 2>&1 || true
        grep '\[BUG\]' "$c.out" | tee -a "$BUGS"
    done
fi

echo "[+] Computing summary"
# compute but do not print queue summary
"$ANALYZER" --summarize --abi ./contract.abi ".corpus/" >> queue_tx_summary
echo "[+] Crashes Summary $crash_dir"
"$ANALYZER" --summarize --abi ./contract.abi "findings_min/" \
    | tee -a crashes_tx_summary

cut -d '|' -s -f 1 < "$BUGS" | sort | uniq -c > "$BUGTYPES"

echo "[+] cleanup"
set -x
sleep 1
pkill -KILL fuzz_multitx || true
sleep 1
# clean up core files
find . -name "core" -delete || true
set +x

echo "[$0 $*] is done"
exit 0
