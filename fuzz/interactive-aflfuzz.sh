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

if [[ -z "$FUZZ_POWER_SCHED" ]]; then
    FUZZ_POWER_SCHED="rare"
fi

if [[ -z "$TMUX" ]]; then
    TMUX=""
fi

set -u

echo "$# args: $*"

echo "[AFL] sanity check"
test -e ./contracts && test -e ./fuzz && test -e ./fuzz/abi
SOURCE_DIR="$(pwd)"
echo "[AFL] good - running in SOURCE_DIR=$SOURCE_DIR"

# 4 hours fuzzing time per contract
FUZZING_TIME="$(python -c "print(4 * 60 * 60)")"
POSTFIX=""


MUTATOR_PATH=""
for try_path in "../ethmutator" "../../ethmutator" "../../ethmutator.git" "/src/ethmutator"; do
    if test -e "$try_path/Cargo.toml"; then
        MUTATOR_PATH="$try_path"
        break
    fi
done
if [[ -n "$MUTATOR_PATH" ]]; then
    MUTATOR_PATH="$(realpath "$MUTATOR_PATH")"
fi
export MUTATOR_PATH
pushd "$MUTATOR_PATH"

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
    env CC=clang CXX=clang++ RUSTFLAGS="-A warnings" cargo build -q "$cargo_arg" || true
    MUT_LIB="$(realpath "$(pwd)/target/$MUT_TYPE/libafl_ethmutator.so")"
    ANALYZER="$(realpath "$(pwd)/target/$MUT_TYPE/efuzzcaseanalyzer")"
    MINIMIZER="$(realpath "$(pwd)/target/$MUT_TYPE/efuzzcaseminimizer")"
    popd
fi

export RUST_BACKTRACE=1
popd

AFL_PATH="$(realpath ../AFLplusplus/)"
test -x "$AFL_PATH/afl-fuzz" && export PATH="$AFL_PATH:$PATH"
command -v afl-fuzz || (echo "couldn't find afl-fuzz in $PATH" && false)

# s.t. afl doesn't complain, and the crashes do not spam core-files
if [[ "$(sysctl -n kernel.core_pattern)" != "core" ]]; then
    $SUDO sysctl -w kernel.core_pattern=core || true
fi
if [[ "$(sysctl -n kernel.core_uses_pid)" -ne 0 ]]; then
    $SUDO sysctl -w kernel.core_uses_pid=0 || true
fi

export AFL_HANG_TMOUT="1000"
AFL_CORES=1
AFL_BENCH_UNTIL_CRASH=
POSTFIX=""
AFL_DICT=
EVM_PROPERTY_PATH=""

# it seems CMPLOG builds sometimes need quite a big map size? default is 2**16;
# but we switch to 2**18 - should work for quite some contracts, no?
AFL_MAP_SIZE="$(python -c "print(2**18)")"
export AFL_MAP_SIZE

CMPLOG_DISABLED="0"
CMPLOG_ARG="2AT"

### Argument parsing

function print_help {
    cat <<EOF
Usage: $0 [OPTION]... <TARGET_CONTRACT>
Launch an interactive AFL++ fuzzing session using tmux/tmuxp
This script allows to quickly set up a fuzzing experiment with a contract.

Some options to configure the fuzzing run:
  --fuzzwd-postfix "<string>"           append string to fuzzing directory
  -t, --time, --fuzzing-time <int>      time in seconds for the fuzzing run
  -c, --cores <int>                     number of cores/AFL instances
  -b, --bench-until-crash               run until the first crash is discovered
  -p, --power-schedule                  set AFL++'s power schedule
  -P, --property-signatures             enable property checking. Pass the path to the property file.
  --disable-abi                         disable passing the ABI to the custom mutator
  --disable-mutator                     disable custom mutator alltogether
  --disable-dict                        disable passing contract dictionary (AFL++ autodict still active)
  --disable-cmplog                      disable AFL++ cmplog (redqueen input-to-state)
  -l, --cmplog-opts "<string>"          pass the following as AFL cmplog opts (default: $CMPLOG_ARG)
  -h, --help                            print this help

EOF
}

POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]
do
key="$1"
case "$key" in
    --fuzzwd-postfix)
    POSTFIX="_$1"
    shift; shift
    ;;
    -t|--time|--fuzzing-time)
    FUZZING_TIME="$1"
    shift; shift
    ;;
    -c|--cores)
    AFL_CORES="$2"
    [[ $AFL_CORES -eq 0 ]] && echo "invalid number of cores!" && exit 1
    shift; shift
    ;;
    --disable-abi)
    ABI_PATH=""
    shift;
    ;;
    --disable-mutator)
    MUT_LIB=""
    shift;
    ;;
    --disable-dict)
    DICT_PATH=""
    shift;
    ;;
    --disable-cmplog)
    CMPLOG_DISABLED="1"
    shift;
    ;;
    -l|--cmplog-opts)
    CMPLOG_ARG="$2"
    shift; shift;
    ;;
    -P|--property-signatures)
    EVM_PROPERTY_PATH="$2"
    shift; shift;
    ;;
    -m|--memory-limit)
    MEMORY_LIMIT="$2"
    shift; shift;
    ;;
    -b|--bench-until-crash)
    export AFL_BENCH_UNTIL_CRASH=1
    shift;
    ;;
    -p|--power-schedule)
    FUZZ_POWER_SCHED="$2"
    shift; shift;
    ;;
    -h|--help)
    print_help
    exit 0
    ;;
    -*|--*)
    echo "unkown option: $key"
    exit 1
    ;;
    *)
    POSITIONAL_ARGS+=("$1")
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

if (( $# == 0 )); then
    print_help
    exit 1
fi

TARGET_CONTRACT="$1"
DICT_PATH="$(realpath -m ./fuzz/dict/$TARGET_CONTRACT.dict)"
test -e "$DICT_PATH" || echo "need dictionary file at $DICT_PATH for this experiment"
ABI_PATH="$(realpath -m ./fuzz/abi/$TARGET_CONTRACT.abi)"
test -e "$ABI_PATH" || echo "need ABI file at $ABI_PATH for this experiment"
TIMESTAMP="$(date +%Y-%m-%dT%H-%M-%S)"
mkdir -p ./fuzz/out || true
FUZZ_CWD="$(realpath -m "./fuzz/out/${TARGET_CONTRACT}_${TIMESTAMP}$POSTFIX/")"
TAR_NAME="$(basename "$FUZZ_CWD")"
BUILD_DIR="$(realpath -m "./fuzz/build/afuzz/$TARGET_CONTRACT")"
CMP_BUILD_DIR="$(realpath -m "./fuzz/build/afuzz_cmplog/$TARGET_CONTRACT")"
BBLIST_PATH="$(realpath ./contracts/${TARGET_CONTRACT}.bb_list)"
GENERIC_SEEDS="$(realpath -m ./fuzz/generic_seeds)"
EVM_DIR="$(realpath -m ./)"

if [[ -e "$EVM_PROPERTY_PATH" ]]; then
    echo "[PROPERTY] ENABLED - Checking properties listed in \"${EVM_PROPERTY_PATH}\"!"
    export EVM_PROPERTY_PATH
else 
    EVM_PROPERTY_PATH=""
    #echo "[PROPERTY] DISABLED - Fuzzing without property checking!"
fi

echo "[+] cleaning up fuzz working dir"
if test -d "$FUZZ_CWD"; then
    $SUDO umount "$FUZZ_CWD" || true
    rm -rf "$FUZZ_CWD"/ || true
fi
if test -L "$FUZZ_CWD"; then
    rm -rf "$FUZZ_CWD"/ || true
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
rm -r m0 s0 s1 s2 s3 default >/dev/null 2>&1 || true
popd


echo "[+] Building target ($BUILD_DIR, $CMP_BUILD_DIR)"
if test -e "$BUILD_DIR" && test -e "$CMP_BUILD_DIR"; then
    export AFL_LLVM_BLOCKLIST="$SOURCE_DIR/fuzz/cov-blocklist.txt"
    pushd "$BUILD_DIR"; ninja fuzz_multitx; popd
    unset AFL_LLVM_BLOCKLIST
    unset AFL_LLVM_ALLOWLIST
    export AFL_LLVM_CMPLOG=1
    pushd "$CMP_BUILD_DIR"; ninja fuzz_multitx; popd
else 
    ./quick-build.sh afuzz "$TARGET_CONTRACT"
fi

pushd "$FUZZ_CWD"
echo "[+] preparing fuzzing working dir"

cat > fuzz-config.sh <<EOF
TARGET_CONTRACT=$1
SOURCE_DIR=$SOURCE_DIR
FUZZING_TIME=$FUZZING_TIME
AFL_MAP_SIZE=$AFL_MAP_SIZE
AFL_BENCH_UNTIL_CRASH=$AFL_BENCH_UNTIL_CRASH
FUZZ_CWD=$FUZZ_CWD
BUILD_DIR=$BUILD_DIR
CMP_BUILD_DIR=$CMP_BUILD_DIR
ABI_PATH=$ABI_PATH
MUTATOR_PATH=$MUTATOR_PATH
DICT_PATH=$DICT_PATH
FUZZ_POWER_SCHED=$FUZZ_POWER_SCHED
EVM_PROPERTY_PATH=$EVM_PROPERTY_PATH
EOF
env | grep "EVM_" >> fuzz-config.sh || true
env | grep "EM_" >> fuzz-config.sh || true
cat fuzz-config.sh

ln -s "$DICT_PATH" "dict"
ln -s "$ABI_PATH" "contract.abi"
ln -s "$BBLIST_PATH" "contract.bb_list"
ln -s "$BUILD_DIR" "build"

cat > r.sh <<EOF
#!/usr/bin/bash
set -ux
export EVM_DEBUG_PRINT=1
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
#!/usr/bin/bash
set -eux
ANALYZER=$ANALYZER
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
#!/usr/bin/bash
set -eux
MINIMIZER=$MINIMIZER
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
#!/usr/bin/bash
python3 $EVM_DIR/fuzz/crash-chain.py \$1 | fzf --preview './a.sh {}'
EOF
chmod +x a.sh r.sh m.sh c.sh

rm -rf seeds || true
mkdir -p seeds || true
printf "\x00" > seeds/nullbyte
if test -d "$GENERIC_SEEDS"; then
    cp "$GENERIC_SEEDS"/*.bin ./seeds/ || true
fi

echo "==========================================================="
echo "testing harness binary with empty seed input:"
env EVM_DEBUG_PRINT=1 EVM_DUMP_STATE="./state" ./build/fuzz_multitx seeds/nullbyte
echo "==========================================================="


AFL_ENV_STR="AFL_HANG_TMOUT=$AFL_HANG_TMOUT "
if [[ -n "$AFL_BENCH_UNTIL_CRASH" ]]; then
    AFL_ENV_STR="$AFL_ENV_STR AFL_BENCH_UNTIL_CRASH=$AFL_BENCH_UNTIL_CRASH"
fi
if [[ -n "$MUT_LIB" ]]; then
    AFL_ENV_STR="$AFL_ENV_STR AFL_CUSTOM_MUTATOR_LIBRARY=\"$MUT_LIB\""
fi
if [[ -n "$ABI_PATH" ]]; then
    AFL_ENV_STR="$AFL_ENV_STR CONTRACT_ABI=\"$ABI_PATH\""
fi
if [[ -n "$DICT_PATH" ]]; then
    AFL_ENV_STR="$AFL_ENV_STR CONTRACT_DICT=\"$DICT_PATH\""
    AFL_DICT="-x \"$DICT_PATH\""
fi
AFL_CMPLOG=""
if [[ "$CMPLOG_DISABLED" -eq 0 ]]; then
    AFL_CMPLOG="-c $CMP_BUILD_DIR/fuzz_multitx"
    if [[ -n "$CMPLOG_ARG" ]]; then 
        AFL_CMPLOG="$AFL_CMPLOG -l $CMPLOG_ARG"
    fi
fi
AFL_ENV_STR="$AFL_ENV_STR EVM_PROPERTY_PATH=$EVM_PROPERTY_PATH"

# timeout in milliseconds; the default of 20ms seems to be too large
#AFL_EXEC_TIMEOUT="-t 50"
AFL_EXEC_TIMEOUT=""

echo "[+] explicitly passing the following ENV args to AFL:"
echo "env $AFL_ENV_STR"

YML="/tmp/afl-$TAR_NAME-$TIMESTAMP.tmuxp.yaml"
cat > "$YML" <<EOF
session_name: afl-$TAR_NAME-$TIMESTAMP
windows:
  - window_name: watch
    layout: tiled
    panes:
      - shell_command:
          - read _continue
          - for x in ./*/crashes/id*; do echo "\$x"; $ANALYZER --abi "$ABI_PATH" "\$x"; echo ""; done;
  #- window_name: backup
  #  layout: tiled
  #  panes:
  #    - shell_command:
  #        - mkdir -p "$FUZZ_CWD/../../out.bak" || true
  #        - cd $FUZZ_CWD/..; watch -n 600 tar -hcJf "$FUZZ_CWD/../../out.bak/afl-$TAR_NAME-$TIMESTAMP.tar.xz" "$(basename "$FUZZ_CWD")";
  - window_name: fuzz
    layout: tiled
    panes:
EOF

if [[ $AFL_CORES -eq 1 ]]; then
    cat >> "$YML" <<EOF
      - shell_command:
          - date > start; 
          - time env $AFL_ENV_STR EM_ALLOW_COMPTRACE=1 afl-fuzz -p $FUZZ_POWER_SCHED -m $MEMORY_LIMIT -i seeds -o . $AFL_EXEC_TIMEOUT $AFL_DICT $AFL_CMPLOG -- $BUILD_DIR/fuzz_multitx;
          - date > end;
EOF
elif [[ $AFL_CORES -eq 2 ]]; then
    cat >> "$YML" <<EOF
      - shell_command:
          - date > start_m0; 
          - time env $AFL_ENV_STR EM_ALLOW_COMPTRACE=1 afl-fuzz -M m0 -p $FUZZ_POWER_SCHED -m $MEMORY_LIMIT -i seeds -o . $AFL_EXEC_TIMEOUT $AFL_DICT $AFL_CMPLOG -- $BUILD_DIR/fuzz_multitx;
          - date > end_m0;
      - shell_command:
          - date > start_w0; 
          - time env $AFL_ENV_STR EM_ALLOW_COMPTRACE=0 afl-fuzz -S w0 -p $FUZZ_POWER_SCHED -m $MEMORY_LIMIT -i seeds -o . $AFL_EXEC_TIMEOUT $AFL_DICT -- $BUILD_DIR/fuzz_multitx;
          - date > end_w0;
EOF
elif [[ $AFL_CORES -eq 3 ]]; then
    cat >> "$YML" <<EOF
      - shell_command:
          - date > start_m0; 
          - time env $AFL_ENV_STR EM_ALLOW_COMPTRACE=0 afl-fuzz -M m0 -D -p $FUZZ_POWER_SCHED -m $MEMORY_LIMIT -i seeds -o . $AFL_EXEC_TIMEOUT $AFL_DICT -- $BUILD_DIR/fuzz_multitx;
          - date > end_m0;
      - shell_command:
          - date > start_w0; 
          - time env $AFL_ENV_STR EM_ALLOW_COMPTRACE=1 afl-fuzz -S c1 -p $FUZZ_POWER_SCHED -m $MEMORY_LIMIT -i seeds -o . $AFL_EXEC_TIMEOUT $AFL_DICT  $AFL_CMPLOG -- $BUILD_DIR/fuzz_multitx;
          - date > end_w0;
      - shell_command:
          - date > start_w2; 
          - time env $AFL_ENV_STR EM_ALLOW_COMPTRACE=0 afl-fuzz -S w2 -p $FUZZ_POWER_SCHED -m $MEMORY_LIMIT -i seeds -o . $AFL_EXEC_TIMEOUT $AFL_DICT -- $BUILD_DIR/fuzz_multitx;
          - date > end_w2;
EOF
else
    cat >> "$YML" <<EOF
      - shell_command:
          - date > start_m0; 
          - time env $AFL_ENV_STR EM_ALLOW_COMPTRACE=0 afl-fuzz -M m0 -D -p $FUZZ_POWER_SCHED -m $MEMORY_LIMIT -i seeds -o . $AFL_EXEC_TIMEOUT $AFL_DICT -- $BUILD_DIR/fuzz_multitx;
          - date > end_m0;
      - shell_command:
          - date > start_w0; 
          - time env $AFL_ENV_STR EM_ALLOW_COMPTRACE=1 afl-fuzz -S c1 -p $FUZZ_POWER_SCHED -m $MEMORY_LIMIT -i seeds -o . $AFL_EXEC_TIMEOUT $AFL_DICT  $AFL_CMPLOG -- $BUILD_DIR/fuzz_multitx;
          - date > end_w0;
      - shell_command:
          - date > start_e2; 
          - time env $AFL_ENV_STR AFL_CUSTOM_MUTATOR_ONLY=1 EM_ALLOW_COMPTRACE=0 afl-fuzz -S e2 -p $FUZZ_POWER_SCHED -m $MEMORY_LIMIT -i seeds -o . $AFL_EXEC_TIMEOUT $AFL_DICT -- $BUILD_DIR/fuzz_multitx;
          - date > end_e2;
EOF

    for i in $(seq 3 "$AFL_CORES" | head -n -1); do
        echo "core $i"
        cat >> "$YML" <<EOF
      - shell_command:
          - date > start_w$i; 
          - time env $AFL_ENV_STR EM_ALLOW_COMPTRACE=0 afl-fuzz -S w$i -p $FUZZ_POWER_SCHED -m $MEMORY_LIMIT -i seeds -o . $AFL_EXEC_TIMEOUT $AFL_DICT -- $BUILD_DIR/fuzz_multitx;
          - date > end_w$i;
EOF
    done
fi
if [[ -n "$TMUX" ]]; then
    exec tmuxp load -a "$YML"
else
    exec tmuxp load  "$YML"
fi
