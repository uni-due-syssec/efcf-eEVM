#!/usr/bin/env bash
set -e -o pipefail

##############################################################################
# here we initialize all variables that could also be set via the environment.
# We want to make sure they have sane default values without overwriting any
# user provided env vars.

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
    MEMORY_LIMIT="2000"
fi

if [[ -z "$FUZZ_SEEDS_DIR" ]]; then
    FUZZ_SEEDS_DIR=""
fi

if [[ -z "$FUZZ_LAUNCHER_DONT_REBUILD" ]]; then
    FUZZ_LAUNCHER_DONT_REBUILD=0
fi

if [[ -z "$FUZZ_POWER_SCHED" ]]; then
    FUZZ_POWER_SCHED="rare"
fi

if [[ -z "$USE_CUSTOM_MUTATOR" ]]; then
    USE_CUSTOM_MUTATOR=1
fi

if [[ -z "$EVM_PROPERTY_PATH" ]]; then
    EVM_PROPERTY_PATH=""
fi

if [[ -z "$EVM_LOAD_STATE" ]]; then
    EVM_LOAD_STATE=""
fi
if [[ -n "$EVM_STATE_LOAD" ]]; then
    export EVM_LOAD_STATE="$EVM_STATE_LOAD"
fi

if [[ -z "$FUZZ_CLEANUP_KILLS" ]]; then
    FUZZ_CLEANUP_KILLS="y"
fi
if [[ -z "$DICT_PATH" ]]; then
    DICT_PATH=""
fi
if [[ -z "$EFCF_INSTALL_DIR" ]]; then
    EFCF_INSTALL_DIR=""
fi

if [[ -z "$FUZZ_NO_SUDO" ]]; then
    FUZZ_NO_SUDO=""
fi

if [[ -z "$FUZZ_PRINT_ENV_CONFIG" ]]; then
    FUZZ_PRINT_ENV_CONFIG=0
fi

if [[ -z "$AFL_MAP_SIZE" ]]; then
    # it seems CMPLOG builds sometimes need quite a big map size? default is 2**16;
    # but we switch to 2**18 - should work for quite some contracts, no?
    export AFL_MAP_SIZE="$(python -c "print(2**18)")"
fi

if [[ -z "$FUZZ_CMPLOG_ARG" ]]; then
    # cmplog level 2 seems to be the most useful as it does not disable
    # trimming, which seems beneficial in our case
    FUZZ_CMPLOG_ARG="-l 2AT"
fi

if [[ -z "$FUZZ_EXEC_TIMEOUT" ]]; then
    FUZZ_EXEC_TIMEOUT=""
fi

if [[ -z "$FUZZING_TIME" ]]; then
    # 4 hours fuzzing time per contract
    FUZZING_TIME="$(python -c "print(4 * 60 * 60)")"
    export FUZZING_TIME
fi

if [[ -z "$FUZZ_CORES" ]]; then
    export FUZZ_CORES=1
fi

if [[ -z "$IGNORE_ABI" ]]; then
    IGNORE_ABI=0
fi

if [[ -z "$ABI_PATH" ]]; then
    ABI_PATH=""
fi

if [[ -z "$EVM_TARGET_MULTIPLE_ADDRESSES" ]]; then
    EVM_TARGET_MULTIPLE_ADDRESSES=""
fi

if [[ -z "$FUZZ_EVMCOV" ]]; then
    FUZZ_EVMCOV=1
fi

if [[ -z "$FUZZ_PLOT" ]]; then
    FUZZ_PLOT=1
fi

if [[ -z "$STACK_ULIMIT" ]]; then
    STACK_ULIMIT="unlimited"
fi

##############################################################################
# all vars must be defined from now on.
set -u

SUDO=""
if command -v sudo; then
    SUDO=sudo
fi

# echo "$# args: $*"

echo "[AFL] sanity check"
test -e ./contracts && test -e ./fuzz && test -e ./fuzz/abi
SOURCE_DIR="$(pwd)"
echo "[AFL] good - running in SOURCE_DIR=$SOURCE_DIR"

echo "[AFL] utilizing $FUZZ_CORES cores"

if (( $# >= 2 )); then
    if [[ -n "$2" ]]; then
        FUZZING_TIME="$2"
    fi
fi
POSTFIX=""
if (( $# >= 3 )); then
    POSTFIX="$3"
fi
echo "[AFL] fuzzing time is $FUZZING_TIME"

MUTATOR_PATH=""
for try_path in "../ethmutator" "../../ethmutator" \
        "../../ethmutator.git" \
        "$EFCF_INSTALL_DIR/src/ethmutator";
do
    if test -e "$try_path/Cargo.toml"; then
        MUTATOR_PATH="$try_path"
        break
    fi
done
if [[ -n "$MUTATOR_PATH" ]]; then
    MUTATOR_PATH="$(realpath "$MUTATOR_PATH")"
fi

if test -d ../AFLplusplus; then
    AFL_PATH="$(realpath ../AFLplusplus/)"
    test -x "$AFL_PATH/afl-fuzz" && export PATH="$AFL_PATH:$PATH"
fi

printf "Using afl-fuzz from: "
command -v afl-fuzz || (echo "couldn't find afl-fuzz in $PATH" && false)

# s.t. afl doesn't complain, and the crashes do not spam core-files
if [[ "$(sysctl -n kernel.core_pattern)" != "core" ]]; then
    if [[ "$FUZZ_NO_SUDO" -eq 1 ]]; then
        export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    else
        set -x
        $SUDO sysctl -w kernel.core_pattern=core || true
        set +x
    fi
fi
if [[ "$(sysctl -n kernel.core_uses_pid)" -ne 0 ]]; then
    if [[ "$FUZZ_NO_SUDO" -eq 1 ]]; then
        export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    else
        set -x
        $SUDO sysctl -w kernel.core_uses_pid=0 || true
        set +x
    fi
fi

TARGET_CONTRACT="$1"

if [[ -z "$DICT_PATH" ]]; then
    TARGET_DICT_PATH="$(realpath -m ./fuzz/dict/$TARGET_CONTRACT.dict)"
    DICT_PATH="$TARGET_DICT_PATH"
    test -e "$DICT_PATH" || echo "need dictionary file at $DICT_PATH for this experiment"
else
    DICT_PATH="$(realpath "$DICT_PATH")"
fi


if [[ -z "$EVM_TARGET_MULTIPLE_ADDRESSES" ]]; then
    # single contract fuzzing mode
    if [[ -z "$ABI_PATH" ]]; then
        ABI_PATH="$(realpath -m ./fuzz/abi/$TARGET_CONTRACT.abi)"
        if ! test -e "$ABI_PATH"; then
            echo "no ABI file at $ABI_PATH - not using ABI for this experiment"
            ABI_PATH=""
        fi
    else
        ABI_PATH="$(realpath "$ABI_PATH")"
    fi
else
    # multi contract fuzzing mode
    if [[ -z "$ABI_PATH" ]]; then
        ABI_PATH=""
        readarray -d "," -t contracts <<< "$EVM_TARGET_MULTIPLE_ADDRESSES"
        for contract in "${contracts[@]}"; do
            contract=$(echo "$contract")
            abi="$(realpath -m "./fuzz/abi/$contract.abi")"
            if [[ -e "$abi" ]]; then
                if [[ -z "$ABI_PATH" ]]; then
                    ABI_PATH="$abi"
                else
                    ABI_PATH="$ABI_PATH,$abi"
                fi
            else
                echo "[+] WARNING: will not use ABIs! could not find abi for $contract (searched $abi) "
                ABI_PATH=""
                break
            fi
        done
    else
        readarray -d "," -t contracts <<< "$EVM_TARGET_MULTIPLE_ADDRESSES"
        readarray -d "," -t abis <<< "$ABI_PATH"
        ABI_PATH=""
        for abi in "${abis[@]}"; do
            abi="$(realpath -m "$abi")"
            if [[ -e "$abi" ]]; then
                if [[ -z "$ABI_PATH" ]]; then
                    ABI_PATH="$abi"
                else
                    ABI_PATH="$ABI_PATH,$abi"
                fi
            else
                echo "[+] WARNING: will not use ABIs! could not find abi $abi"
                ABI_PATH=""
                break
            fi
        done
    fi
fi

BBLIST_PATH="$(realpath ./contracts/${TARGET_CONTRACT}.bb_list)"

GENERIC_SEEDS="$(realpath -m ./fuzz/generic_seeds)"
EVM_DIR="$(realpath -m ./)"

if [[ -n "$EVM_LOAD_STATE" ]]; then
    export EVM_LOAD_STATE="$(realpath "$EVM_LOAD_STATE")"
fi

if [[ -z "$EVM_PROPERTY_PATH" ]]; then
    EVM_PROPERTY_PATH="${SOURCE_DIR}/fuzz/properties/${TARGET_CONTRACT}.signatures"
    if test -e "$EVM_PROPERTY_PATH"; then
        export EVM_PROPERTY_PATH
    else
        EVM_PROPERTY_PATH=""
        #echo "[PROPERTY] DISABLED - Fuzzing without property checking!"
    fi
fi

if [[ -n "$EVM_PROPERTY_PATH" ]]; then
    echo "[PROPERTY] ENABLED - Checking the properties listed in \"${EVM_PROPERTY_PATH}\"!"
    if [[ -e "$EVM_PROPERTY_PATH" ]]; then
        export EVM_PROPERTY_PATH="$(realpath "$EVM_PROPERTY_PATH")"
    else
        echo "[ERROR] cannot find EVM_PROPERTY_PATH=$EVM_PROPERTY_PATH"
        exit 1
    fi
fi

mkdir -p ./fuzz/out || true
FUZZ_CWD="$(realpath -ms "./fuzz/out/${TARGET_CONTRACT}_$(basename "$0" | cut -f 1 -d '.')_$POSTFIX")"

BUILD_DIR="$(realpath -m "./fuzz/build/afuzz/$TARGET_CONTRACT")"
CMP_BUILD_DIR="$(realpath -m "./fuzz/build/afuzz_cmplog/$TARGET_CONTRACT")"

export AFL_MAP_SIZE


if test -d "$FUZZ_CWD"; then
    if [[ "$FUZZ_NO_SUDO" -ne 1 ]]; then
        $SUDO umount "$FUZZ_CWD" || true
    fi
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
        if [[ "$FUZZ_NO_SUDO" -ne 1 ]]; then
            $SUDO mount -t tmpfs - "$FUZZ_CWD" || true
        fi
    fi
fi

echo "[+] checking build"
if [[ -z "$MUTATOR_PATH" ]]; then
    MUT_LIB="/usr/local/lib/libafl_ethmutator.so"
    test -e "$MUT_LIB" || (echo "failed to find AFL++ custom mutator library!" && false)
    ANALYZER="$(command -v efuzzcaseanalyzer)"
    MINIMIZER="$(command -v efuzzcaseminimizer)"
else
    pushd "$MUTATOR_PATH"
    cargo_arg="--$MUT_TYPE"
    if [[ "$MUT_TYPE" == "debug" ]]; then
        cargo_arg=""
    fi
    if [[ "$FUZZ_LAUNCHER_DONT_REBUILD" -ne 1 ]]; then
        echo "[+] Rebuilding custom mutator (just in case)"
        env CC=clang CXX=clang++ RUSTFLAGS="-A warnings" cargo build -q "$cargo_arg" || true
    fi
    MUT_LIB="$(realpath "$(pwd)/target/$MUT_TYPE/libafl_ethmutator.so")"
    ANALYZER="$(realpath "$(pwd)/target/$MUT_TYPE/efuzzcaseanalyzer")"
    MINIMIZER="$(realpath "$(pwd)/target/$MUT_TYPE/efuzzcaseminimizer")"
    popd
fi

if test -e "$BUILD_DIR" && test -e "$CMP_BUILD_DIR"; then
    if [[ "$FUZZ_LAUNCHER_DONT_REBUILD" -ne 1 ]]; then
        echo "[+] build found - launching quick re-build (in case anything changed)"
        export AFL_LLVM_BLOCKLIST="$SOURCE_DIR/fuzz/cov-blocklist.txt"
        pushd "$BUILD_DIR"; ninja fuzz_multitx; popd
        unset AFL_LLVM_BLOCKLIST
        unset AFL_LLVM_ALLOWLIST
        export AFL_LLVM_CMPLOG=1
        pushd "$CMP_BUILD_DIR"; ninja fuzz_multitx; popd
    fi
else
    echo "[+] no build found - launching build"
    ./quick-build.sh afuzz "$TARGET_CONTRACT"
fi

cd "$FUZZ_CWD"
echo "[+] running afl-fuzz in directory: $(pwd)"

if test -e "$DICT_PATH"; then
    ln -s "$DICT_PATH" "dict"
elif [[ -z "$EVM_LOAD_STATE" ]]; then
    if [[ "$TARGET_DICT_PATH" == "$DICT_PATH" ]]; then
        cp "$DICT_PATH" "dict"
        export DICT_PATH="$(realpath ./dict)"
        echo "[+] updating dictionary with all addresses from state"
        python3 "$SOURCE_DIR/fuzz/state2dict.py" "$EVM_LOAD_STATE" >> dict.new
        echo "[+] updating dictionary with content from all known contracts!"
        cat "$SOURCE_DIR/fuzz/dict/"*.dict >> dict.new
        cat dict >> dict.new
        cat dict.new | sort -u > dict
        rm dict.new
        echo "combined dictionary with $(cat dict | wc -l) entries"
    fi
fi

# unset CONTRACT_ABI # ???
CONTRACT_ABI=""
if [[ "$IGNORE_ABI" -eq 0 ]]; then
    CONTRACT_ABI="$ABI_PATH"
fi

cat > fuzz-config.sh <<EOF
TARGET_CONTRACT=$TARGET_CONTRACT
FUZZING_TIME=$FUZZING_TIME
SOURCE_DIR=$SOURCE_DIR
DICT_PATH=$DICT_PATH
AFL_MAP_SIZE=$AFL_MAP_SIZE
CONTRACT_ABI=$CONTRACT_ABI
IGNORE_ABI=$IGNORE_ABI
ABI_PATH=$ABI_PATH
FUZZ_CWD=$FUZZ_CWD
BUILD_DIR=$BUILD_DIR
CMP_BUILD_DIR=$CMP_BUILD_DIR
FUZZ_CORES=$FUZZ_CORES
FUZZ_POWER_SCHED=$FUZZ_POWER_SCHED
USE_CUSTOM_MUTATOR=$USE_CUSTOM_MUTATOR
AFL_LLVM_BLOCKLIST=$SOURCE_DIR/fuzz/cov-blocklist.txt
EOF
# EVM_PROPERTY_PATH=$EVM_PROPERTY_PATH
# EVM_TARGET_MULTIPLE_ADDRESSES=$EVM_TARGET_MULTIPLE_ADDRESSES
env | grep "EVM_" >> fuzz-config.sh || true
env | grep "EM_" >> fuzz-config.sh || true

if [[ "$FUZZ_PRINT_ENV_CONFIG" -eq 1 ]]; then
    cat fuzz-config.sh
fi


rm -r default m0 s* >/dev/null 2>&1 || true

if [[ -n "$ABI_PATH" ]]; then
    if [[ -e "$ABI_PATH" ]]; then
        ln -s "$ABI_PATH" "contract.abi" || true
    fi
fi
ln -s "$BBLIST_PATH" "contract.bb_list"
ln -s "$BUILD_DIR" "build"

cat > r.sh <<EOF
#!/usr/bin/env bash
set -u
export EVM_DEBUG_PRINT=1
if test -e ./fuzz-config.sh; then
    export \$(cat ./fuzz-config.sh)
fi
ANALYZER=$ANALYZER
if ! command -v "\$ANALYZER" >/dev/null; then
    ANALYZER=efuzzcaseanalyzer
fi
if test -e ./build/fuzz_multitx; then
    ./build/fuzz_multitx \$1
elif test -e ./fuzz_multitx; then
    ./fuzz_multitx \$1
else
    echo "can't find fuzz_multitx binary"
    find . -name "fuzz_multitx"
    exit 1
fi
if test -e ./contract.abi; then
    \$ANALYZER -a ./contract.abi \$1
else
    \$ANALYZER \$1
fi
EOF
cat > a.sh <<EOF
#!/usr/bin/env bash
set -eu
ANALYZER=$ANALYZER
if test -e ./fuzz-config.sh; then
    export \$(cat ./fuzz-config.sh)
fi
if ! command -v "\$ANALYZER" >/dev/null; then
    ANALYZER=efuzzcaseanalyzer
fi
if test -e ./contract.abi; then
    \$ANALYZER -a ./contract.abi \$@
else
    \$ANALYZER \$@
fi
EOF
cat > m.sh <<EOF
#!/usr/bin/env bash
set -eu
MINIMIZER=$MINIMIZER
if test -e ./fuzz-config.sh; then
    export \$(cat ./fuzz-config.sh)
fi
if ! command -v "\$MINIMIZER" >/dev/null; then
    MINIMIZER=efuzzcaseminimizer
fi
bin=""
if test -e ./build/fuzz_multitx; then
    bin=./build/fuzz_multitx
elif test -e ./fuzz_multitx; then
    bin=./fuzz_multitx
else
    echo "can't find fuzz_multitx binary"
    find . -name "fuzz_multitx"
    exit 1
fi
testcase=\$1
shift
if test -e ./contract.abi; then
    \$MINIMIZER -a ./contract.abi \$@ \$bin \$testcase
else
    \$MINIMIZER \$@ \$bin \$testcase
fi
EOF
cat > c.sh <<EOF
#!/usr/bin/env bash
EVM_DIR="$EVM_DIR"
if test -e ./fuzz-config.sh; then
    export \$(cat ./fuzz-config.sh)
fi
if ! test -d "\$EVM_DIR"; then
    if test -d "\$EFCF_INSTALL_DIR"; then
        EVM_DIR="\$EFCF_INSTALL_DIR/src/eEVM/"
    fi
    if test -e ./build; then
        rp="\$(realpath ./build/../../../../)"
        if test -d "\$rp/fuzz"; then
            EVM_DIR="\$rp"
        fi
    fi
fi
test -e "\$EVM_DIR" || exit 1
python3 \$EVM_DIR/fuzz/crash-chain.py \$1 | fzf --preview './a.sh {}'
EOF
chmod +x a.sh r.sh m.sh c.sh


rm -rf seeds || true
mkdir -p seeds || true
printf "\x00" > seeds/nullbyte

for seed_dir in "$GENERIC_SEEDS" "$FUZZ_SEEDS_DIR"; do
    if [[ -n "$seed_dir" && -d "$seed_dir" ]]; then
        cp "$seed_dir"/*.bin ./seeds/ || true
        cp "$seed_dir"/*.efcf ./seeds/ || true
    fi
done

echo "==========================================================="
echo "testing harness binary with empty seed input:"
env EVM_DEBUG_PRINT=1 EVM_DUMP_STATE="./state" ./build/fuzz_multitx seeds/nullbyte
echo "==========================================================="

trap "test -e '$PWD/end_default' || date > '$PWD/end_default'" EXIT


function kill_all_afl_fuzz {
    for fstats in ./*/fuzzer_stats; do
        pid="$(sed -n -E -e 's/^fuzzer_pid\s+:\s+([0-9]+)/\1/p' "$fstats")"
        pkill "$pid" || true
    done
    sleep 3
}


function launch_afl_instance {
    afl_instance="$1"
    afl_role="$2"
    date > "start_$afl_instance"

    AFL_MS=""
    if [[ "$afl_instance" == "default" ]]; then
        AFL_MS=""
    else
        case "$afl_instance" in
            m*)
            AFL_MS="-M $afl_instance -D"
            ;;
            *)
            AFL_MS="-S $afl_instance"
            ;;
        esac
    fi
    CMPLOG="-c $CMP_BUILD_DIR/fuzz_multitx $FUZZ_CMPLOG_ARG"
    if [[ "$FUZZ_CMPLOG_ARG" == "none" || -z "$FUZZ_CMPLOG_ARG" ]]; then
        CMPLOG=""
    fi

    ABI_PARAM=""
    if [[ "$IGNORE_ABI" -eq 0 ]]; then
        if [[ -n "$ABI_PATH" ]]; then
            ABI_PARAM="CONTRACT_ABI=$ABI_PATH"
        fi
    fi

    if [[ -n "$MUT_LIB" && "$USE_CUSTOM_MUTATOR" -eq 1 ]]; then
        MUT_PARAM="AFL_CUSTOM_MUTATOR_LIBRARY=$MUT_LIB"
    else
        MUT_PARAM=""
    fi

    if [[ "$afl_role" = "c" ]]; then
        CMPTRACE_PARAM="EM_ALLOW_COMPTRACE=1"
        CMPLOG_PARAM="$CMPLOG"
    elif [[ "$afl_role" = "w" ]]; then
        CMPTRACE_PARAM="EM_ALLOW_COMPTRACE=0"
        CMPLOG_PARAM=""
    elif [[ "$afl_role" = "m" ]]; then
        CMPTRACE_PARAM="EM_ALLOW_COMPTRACE=0"
        CMPLOG_PARAM=""
    elif [[ "$afl_role" = "e" ]]; then
        CMPTRACE_PARAM="EM_ALLOW_COMPTRACE=0"
        CMPLOG_PARAM=""
        MUT_PARAM="$MUT_PARAM AFL_CUSTOM_MUTATOR_ONLY=1"
    fi

    # we disable auto-dict, because we supply a better dictionary, that is
    # generated from the EVM bytecode and contains only relevant data
    export AFL_NO_AUTODICT=1

    # make sure there is no debug printing while fuzzing...
    unset EVM_DEBUG_PRINT || true
    unset EVM_CMP_LOG || true
    unset EVM_COVERAGE_FILE || true

    /usr/bin/time -v -o ./afl.time \
        env AFL_NO_UI=1 \
            $MUT_PARAM \
            CONTRACT_DICT="$DICT_PATH" \
            $ABI_PARAM \
            $CMPTRACE_PARAM \
            EVM_CREATE_TX_INPUT="${EVM_CREATE_TX_INPUT:-""}" \
                afl-fuzz -m "$MEMORY_LIMIT" -i seeds -o . -x "$DICT_PATH" \
                $AFL_MS \
                $FUZZ_EXEC_TIMEOUT \
                $CMPLOG_PARAM \
                -p $FUZZ_POWER_SCHED \
                -V "$FUZZING_TIME" \
                -- "$BUILD_DIR/fuzz_multitx" \
                    2>&1 | tee "afl.$afl_instance.log"

            # we can use flamegraph-rs to profile the fuzzing a bit
                #flamegraph -o flamegraph.svg -- \
                # afl-fuzz ...
            # but you need to uncomment the redirection part for it to work.
                # #2>&1 | tee "afl.$afl_instance.log"

    date > "end_$afl_instance"

    kill_all_afl_fuzz

    if [[ "$FUZZ_CLEANUP_KILLS" == "y" || "$FUZZ_CLEANUP_KILLS" -eq 1 ]]; then
        # stop all other running AFL instances now.
        pkill afl-fuzz || true
    fi
}

if [[ "$FUZZ_CLEANUP_KILLS" == "y" || "$FUZZ_CLEANUP_KILLS" -eq 1 ]]; then
    # make sure there are no stale processes around
    pkill -KILL fuzz_multitx || true
fi


trap "sleep 5; kill_all_afl_fuzz;" SIGTERM SIGINT

echo "[INFO] increasing stack-size limit to: $STACK_ULIMIT"
ulimit -s "$STACK_ULIMIT"

if [[ $FUZZ_CORES -eq 1 ]]; then
    echo "[ENSEMBLE] main (with cmpare logging/tracing enabled)"
    launch_afl_instance default "c"
else
    if [[ "$FUZZ_CORES" -eq 2 ]]; then
        echo "[ENSEMBLE] main (with cmpare logging/tracing enabled)"
        launch_afl_instance "m0" "c" &
        echo "[ENSEMBLE] worker"
        launch_afl_instance "w1" "w" &
    elif [[ "$FUZZ_CORES" -eq 3 ]]; then
        echo "[ENSEMBLE] main (with deterministic)"
        launch_afl_instance "m0" "m" &
        echo "[ENSEMBLE] compare instance (with cmpare logging/tracing enabled)"
        launch_afl_instance "c1" "c" &
        echo "[ENSEMBLE] worker"
        launch_afl_instance "w2" "w" &
    else
        echo "[ENSEMBLE] main (with deterministic)"
        launch_afl_instance "m0" "m" &
        echo "[ENSEMBLE] compare instance (with cmpare logging/tracing enabled)"
        launch_afl_instance "c1" "c" &
        echo "[ENSEMBLE] custom mutator only"
        launch_afl_instance "e2" "e" &
        start_idx=4
        if [[ "$FUZZ_CORES" -gt 16 ]]; then
            echo "[ENSEMBLE] 2nd compare instance (with cmpare logging/tracing enabled)"
            launch_afl_instance "c3" "c" &
            echo "[ENSEMBLE] 2nd custom mutator only"
            launch_afl_instance "e4" "e" &
            start_idx=6
        fi
        schedules=(fast explore rare)
        # and the rest are workers
        for i in $(seq "$start_idx" "$FUZZ_CORES"); do
            j=$((i-1))
            sleep 1
            s=$(( j % 3 ))
            FUZZ_POWER_SCHED=${schedules[$s]}
            echo "[ENSEMBLE] worker $j (with -p $FUZZ_POWER_SCHED)"
            launch_afl_instance "w$j" "w" &
        done
    fi

    wait
fi

trap "" SIGTERM SIGINT


if [[ $FUZZ_EVMCOV -eq 1 ]]; then
    echo "[+] computing EVM-block coverage"
    "$SOURCE_DIR"/fuzz/evm-bb-coverage.sh ./
fi

rm queue_tx_summary crashes_tx_summary || true

if [[ $FUZZ_PLOT -eq 1 ]]; then
    if command -v afl-plot >/dev/null 2>&1; then
        echo "[+] creating plots"
        for d in ./*; do
            if test -d "$d/crashes" && test -d "$d/queue"; then
                mkdir -p "$d/plots" || true
                afl-plot "$d" "$d/plots" || true
            fi
        done
    fi
fi

###################################################################################################
echo "[+] post-processing AFL results"

BUGS="$(realpath "./bugs")"
BUGTYPES="$(realpath "./bugtypes")"
touch "$BUGTYPES"
touch "$BUGS"
CRASHES_MIN="./crashes_min"
mkdir -p "$CRASHES_MIN" || true
FULL_QUEUE="$(realpath "./combined_queue/")"
mkdir -p "$FULL_QUEUE" || true

abi_param=""
if [[ -e ./contract.abi ]]; then
    abi_path="$(realpath ./contract.abi)"
    abi_param="--abi $abi_path"
fi
bin_path="$(realpath ./build/fuzz_multitx)"

for crash_dir in ./*/crashes; do
    afl_instance="$(basename "$(dirname "$crash_dir")")"
    echo "    |-> analyzing dir $crash_dir of $afl_instance"
    cp -r "$crash_dir" "$crash_dir/../crashes_min"
    rm "$crash_dir/../crashes_min/README"* >/dev/null 2>&1 || true

    echo   "    |-> minimizing dir $crash_dir of $afl_instance"
    mkdir -p "$crash_dir/../crashes_min_out/"
    if [[ -n "$(ls -A $crash_dir/../crashes_min/)" ]]; then
        printf "    "
        for f in "$crash_dir/../crashes_min/"*; do
            # echo "    * processing crash $f"
            test -e "$f"

            c="$(realpath "$crash_dir/../crashes_min_out/$(basename "$f")")"
            if "$MINIMIZER" --overwrite $abi_param \
                    "$bin_path" "$f" >"$c.min.log" 2>&1;
            then
                # echo "    minimizer succeeded on $f!"
                printf "."
            else
                echo ""
                echo "    minimizer failed on $f!"
                cat "$c.min.log" || true
            fi

            env EVM_NO_ABORT=1 EVM_DEBUG_PRINT=1 EVM_DUMP_STATE="$c.state" \
                "$bin_path" "$f" >"$c.out" 2>&1 || true
            grep --binary-files=text '\[BUG\]' "$c.out" >> "$BUGS" || true

            # prefix the crash by the afl instance that found it
            cp "$f" "$CRASHES_MIN/${afl_instance}_$(basename "$f")" || true
        done
        echo ""
    fi

    touch "$crash_dir/../crashes_tx_summary"
    touch "$crash_dir/../queue_tx_summary"

    queue_dir="$crash_dir/../queue/"
    if test -e "$queue_dir"; then
        echo "    |-> summarizing dir $queue_dir of $afl_instance"
        "$ANALYZER" --summarize $abi_param "$queue_dir" \
            > "$crash_dir/../queue_tx_summary"

        if [[ -n "$(ls -A "$queue_dir")" ]]; then
            for qentry in "$queue_dir/"*; do
                bn="$(basename "$qentry")"
                cp "$qentry" "$FULL_QUEUE/${afl_instance}_${bn}" || true
            done
        else
            echo "empty queue? wut? you might to fuzz for longer?"
            ls -al "$queue_dir"
        fi
    else
        echo "[-] no queue directory? wut? $queue_dir"
        ls -al "$crash_dir/../"
    fi

    crashmindir="$crash_dir/../crashes_min"
    if [[ -n "$(ls -A "$crashmindir")" ]]; then
        echo "    |-> summarizing dir $crashmindir of $afl_instance"
        "$ANALYZER" --summarize $abi_param "$crashmindir" \
            > "$crash_dir/../crashes_tx_summary" || true
    fi
done

if [[ -n "$(ls -A "$CRASHES_MIN")" ]]; then
    # generate summary over all minimized crashes of all afl instances
    "$ANALYZER" --summarize $abi_param "$CRASHES_MIN" \
        | tee crashes_tx_summary \
        || true
else
    touch crashes_tx_summary
fi
if [[ -n "$(ls -A "$FULL_QUEUE")" ]]; then
    # same for the queue
    "$ANALYZER" --summarize $abi_param "$FULL_QUEUE" \
        > queue_tx_summary
else
    echo "[-] empty queue? this is strange"
    ls -al "$FULL_QUEUE"
    touch queue_tx_summary
fi
# rm -rf "$FULL_QUEUE"

cat "$BUGS" | sort -u
cut -d '|' -s -f 1 < "$BUGS" | sort | uniq -c > "$BUGTYPES"

echo "[+] cleanup"
if [[ "$FUZZ_CLEANUP_KILLS" == "y" || "$FUZZ_CLEANUP_KILLS" -eq 1 ]]; then
    sleep 1
    echo "... killing remaining harness processes"
    pkill -KILL fuzz_multitx || true
    sleep 1
fi
echo "... clean up core files"
find . -name "core" -delete || true

echo "[$0 $*] is done"
exit 0
