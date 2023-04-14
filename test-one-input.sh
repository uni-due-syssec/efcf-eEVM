#!/usr/bin/env bash
set -e -o pipefail

if [[ -z "$FUZZ_LAUNCHER_DONT_REBUILD" ]]; then
    FUZZ_LAUNCHER_DONT_REBUILD=0
fi

# first argument: name of target contract
TARGET_CONTRACT="$1"

# second argument: input file as .bin
INPUT_FILE="$2"

# path to .bin file
INPUT_BIN="$(echo "$INPUT_FILE"| cut -d'.' -f 1).bin"

# path to executable of harness
HARNESS_BIN="/fuzz/build/afuzz/$TARGET_CONTRACT/fuzz_multitx"

# transcode .yaml to .bin
efuzzcasetranscoder "$INPUT_FILE" "$INPUT_BIN"

# build and compare build directory of target directory
BUILD_DIR="$(realpath -m "./fuzz/build/afuzz/$TARGET_CONTRACT")"

# build target contract
echo "[+] Building target ($BUILD_DIR)"
if test -e "$BUILD_DIR"; then
    if [[ "$FUZZ_LAUNCHER_DONT_REBUILD" -ne 1 ]]; then
        pushd "$BUILD_DIR"; ninja fuzz_multitx; popd
    fi
else
    ./quick-build.sh afuzz "$TARGET_CONTRACT"
fi

echo "[+] Executing harness code with $INPUT_BIN"
printf "\n\n"

# execute the harness with given input
."$HARNESS_BIN" "$INPUT_BIN"
