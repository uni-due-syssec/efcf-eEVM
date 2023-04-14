#!/usr/bin/env bash
set -e

export FUZZ_TARGET=nop
if ! test -z "$2"; then
    export FUZZ_TARGET="$2"
fi

if [[ "$DISABLE_CCACHE" -ne 1 ]] ; then
    if [[ -z "$CCACHE_DIR" ]]; then
        CCACHE_DIR=""
    fi
    for ccache_link_dir in /usr/lib/ccache/ /usr/lib/ccache/bin/ /usr/lib64/ccache/; do
        if test -d "$ccache_link_dir" && test -e "$ccache_link_dir/clang"; then
            export PATH="$ccache_link_dir:$PATH"
            if [[ -z "$CCACHE_DIR" ]]; then
                CCACHE_DIR="$(realpath -m .ccache)"
            fi
            export CCACHE_DIR
            export CCACHE_NOHASHDIR=1
            echo "...putting ccache into PATH => $(command -v clang) with CCACHE_DIR=$CCACHE_DIR"
            #export CCACHE_DEBUG=1
            break
        fi
    done
else
    CCACHE_DIR=""
fi

echo "*** Building Target $1 with contract $FUZZ_TARGET ***"

if [[ "$1" == "clean" ]]; then
    set -x
    rm -rf build*
    rm -rf ./fuzz/build/

elif [[ "$1" == "hfuzz" ]]; then
    # best effort to add honggfuzz to path on dev systems
    [[ -d "$HOME/src/honggfuzz" ]] \
        && export PATH=$HOME/src/honggfuzz/:$HOME/src/honggfuzz/hfuzz_cc/:$PATH
    [[ -d "$HOME/.local/honggfuzz" ]] && export PATH=$HOME/.local/honggfuzz/bin/:$PATH
    #rm -rf fuzz_build_hfuzz || true
    export SOURCE_DIR="$(pwd)"
    BUILD_DIR="$(realpath -m "./fuzz/build/hfuzz/$FUZZ_TARGET")"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    set -x
    export CC=hfuzz-clang
    export CXX=hfuzz-clang++
    export AR=llvm-ar
    export CMAKE_AR=llvm-ar
    export RANLIB=llvm-ranlib
    export CMAKE_RANLIB=llvm-ranlib
    cmake \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DLTO_LINKER_NAME=lld \
        -DENABLE_FUZZING=ON \
        -DENABLE_DETECTOR=ON \
        -DFUZZ_TARGET="$FUZZ_TARGET" \
        "$SOURCE_DIR"
    exec time ninja -v
    
elif [[ "$1" == "libfuzzer" ]]; then 

    export SOURCE_DIR="$(pwd)"
    BUILD_DIR="$(realpath -m "./fuzz/build/libfuzzer/$FUZZ_TARGET")"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    set -x
    export CC=clang
    export CXX=clang++
    export AR=llvm-ar
    export CMAKE_AR=llvm-ar
    export RANLIB=llvm-ranlib
    export CMAKE_RANLIB=llvm-ranlib
    cmake \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DLTO_LINKER_NAME=lld \
        -DENABLE_FUZZING=ON \
        -DENABLE_DETECTOR=ON \
        -DLIBFUZZER=ON \
        -DFUZZ_TARGET="$FUZZ_TARGET" \
        "$SOURCE_DIR"

    exec time ninja -v fuzz_multitx

elif [[ "$1" == "afuzz" ]] || [[ "$1" == "afuzz-covonly" ]] || [[ "$1" == "afuzz-interp" ]] ; then
    if ! command -v afl-clang-lto; then
        # best effort to add afl++ to path on dev systems
        [[ -d ../AFLplusplus/ ]] && export PATH="$(realpath ../AFLplusplus/):$PATH"
    fi

    INTERP=
    if [[ "$1" == "afuzz-interp" ]]; then
        INTERP="-DFUZZ_INTERP=ON"
    fi

    export SOURCE_DIR="$(pwd)"
    BUILD_DIR="$(realpath -m "./fuzz/build/afuzz/$FUZZ_TARGET")"
    rm -rf "$BUILD_DIR" || true
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    if [[ "$1" == "afuzz-covonly" ]]; then
        DETECTOR=OFF
    else
        DETECTOR=ON
    fi

    echo "Using CC=$(command -v afl-clang-lto)"
    set -x
    export AFL_CC="$(command -v clang)"
    export AFL_CXX="$(command -v clang++)"
    export CC=afl-clang-lto
    export CXX=afl-clang-lto++
    export AR=llvm-ar
    export CMAKE_AR=llvm-ar
    export RANLIB=llvm-ranlib
    export CMAKE_RANLIB=llvm-ranlib
    export LD=ld.lld
    #export AFL_CC_COMPILER=LTO
    # best effort to find libAFLDriver, which implements main based on LLVMFuzzerTestOneInput
    _AFL_DRIVER="$(realpath "$(dirname "$(command -v "afl-clang-lto")")/libAFLDriver.a")"
    export _AFL_DRIVER
    test -e "$_AFL_DRIVER" || export _AFL_DRIVER=/usr/local/lib/afl/libAFLDriver.a
    test -e "$_AFL_DRIVER" || export _AFL_DRIVER="/usr/lib/afl/libAFLDriver.a"
    test -e "$_AFL_DRIVER" || export _AFL_DRIVER="../AFLplusplus/libAFLDriver.a"
    test -e "$_AFL_DRIVER" || export _AFL_DRIVER="$HOME/src/AFLplusplus/utils/aflpp_driver/libAFLDriver.a"
    test -e "$_AFL_DRIVER" || export _AFL_DRIVER=""
    if [[ "$_AFL_DRIVER" = "" ]]; then
        echo "WARNING: no AFL driver found; compilation might fail due to missing 'main' function"
    fi

    cmake -G Ninja \
        -DDUMP_LTO_BITCODE=OFF \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DENABLE_FUZZING=ON \
        $INTERP \
        -DFUZZ_TARGET="$FUZZ_TARGET" \
        -DENABLE_DETECTOR="$DETECTOR" \
        -DFUZZ_DRIVER_LIB="$_AFL_DRIVER" \
        "$SOURCE_DIR"

    # do not export before cmake, or it will break cmake compiler detection...
    #export AFL_LLVM_ALLOWLIST="$SOURCE_DIR/fuzz/cov-allowlist.txt"
    export AFL_LLVM_BLOCKLIST="$SOURCE_DIR/fuzz/cov-blocklist.txt"
    time ninja -v fuzz_multitx

    # try dumping the llvm code if it exists.
    objcopy fuzz_multitx --dump-section .llvmbc=fuzz_multitx.bc || true

    set +x

    # we instrument everything for cmplog!
    unset AFL_LLVM_BLOCKLIST
    unset AFL_LLVM_ALLOWLIST

    echo "Building CMPLOG binary variant for redqueen style input-to-state"
    cd "$SOURCE_DIR"
    BUILD_DIR="$(realpath -m "./fuzz/build/afuzz_cmplog/$FUZZ_TARGET")"
    rm -rf "$BUILD_DIR" || true
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    set -x
    export AFL_LLVM_CMPLOG=1
    cmake -G Ninja \
        -DDUMP_LTO_BITCODE=OFF \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DENABLE_FUZZING=ON -DFUZZ_TARGET="$FUZZ_TARGET" \
        $INTERP \
        -DENABLE_DETECTOR="$DETECTOR" \
        -DFUZZ_DRIVER_LIB="$_AFL_DRIVER" \
        "$SOURCE_DIR"
    time ninja -v fuzz_multitx
    set +x

    # print some ccache stats
    if command -v ccache && [[ -n "$CCACHE_DIR" && "$DISABLE_CCACHE" -ne 1 ]]; then
        ccache -s
    fi

elif [[ "$1" == "debug" ]]; then
    mkdir -p build_debug
    cd build_debug
    set -x
    export CC=clang
    export CXX=clang++
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug ..
    exec ninja -v

else
    mkdir -p build
    cd build
    set -x
    export CC=clang
    export CXX=clang++
    cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
    exec ninja -v
fi
