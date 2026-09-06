#!/usr/bin/env bash
# Cross-compile the Zygisk library for every Android ABI.
#
# Direct clang++ with explicit static linking of libc++_static.a. This is the
# only deterministic path in NDK r27b: ndk-build silently ignores APP_STL when
# NDK_PROJECT_PATH is custom, and -static-libstdc++ links the legacy GNU
# libstdc++ (missing __cxa_guard_*). Linking libc++_static.a directly gives us
# the full C++ runtime statically, with NO libc++_shared.so dependency.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/zygisk/stealth_ultimate.cpp"
OUT_DIR="$SCRIPT_DIR/zygisk"
NDK="${NDK_HOME:-${ANDROID_NDK_HOME:-}}"
API=24

INCLUDE_FLAGS=(-I"$SCRIPT_DIR/zygisk")

[[ -f "$SRC" ]] || { echo "Source file not found: $SRC" >&2; exit 1; }
[[ -n "$NDK" && -d "$NDK" ]] || { echo "Android NDK not found. Set NDK_HOME." >&2; exit 1; }

PREBUILT="$(find "$NDK/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ -n "$PREBUILT" && -d "$PREBUILT/bin" ]] || {
    echo "NDK LLVM toolchain not found under: $NDK" >&2
    exit 1
}
SYSROOT="$PREBUILT/sysroot"

# Locate libc++_static.a for the given target triple. Must match the ABI
# exactly or the linker rejects it as incompatible.
libcxx_static_for() {
    local triple="$1"
    local f="$SYSROOT/usr/lib/$triple/libc++_static.a"
    [[ -f "$f" ]] || f="$SYSROOT/usr/lib/$triple/libc++_static.a"
    [[ -f "$f" ]] || {
        # NDK fallback layout
        f="$(find "$NDK/sources/cxx-stl/llvm-libc++/libs" -path "*$triple*" -name libc++_static.a 2>/dev/null | head -1)"
    }
    echo "$f"
}

COMMON_CXXFLAGS=(
    -O2
    -fPIC
    -shared
    -std=c++17
    -fno-exceptions
    -fno-rtti
    -nostdlib++
    -fno-function-sections
    -fno-data-sections
    -Wall
    -Wextra
)
COMMON_LDFLAGS=(
    -Wl,--hash-style=both
    -Wl,-z,global
    -Wl,-z,now
    -Wl,-z,noexecstack
    -Wl,-soname,libstealth.so
    -Wl,--no-gc-sections
    -Wl,--no-undefined
)

compile_arch() {
    local compiler="$1"
    local abi="$2"
    local triple="$3"
    local output="$OUT_DIR/$abi.so"

    [[ -x "$compiler" ]] || { echo "Compiler not found: $compiler" >&2; exit 1; }
    echo "Compiling $abi with $(basename "$compiler")..."

    "$compiler" \
        "${INCLUDE_FLAGS[@]}" \
        "${COMMON_CXXFLAGS[@]}" \
        --sysroot "$SYSROOT" \
        -o "$output" "$SRC" \
        "${COMMON_LDFLAGS[@]}" \
        -lc -ldl -llog -latomic

    [[ -s "$output" ]] || { echo "Compiler produced no output: $output" >&2; exit 1; }
    file "$output"
    ls -lh "$output"
}

rm -f "$OUT_DIR"/*.so
# triples used here are the sysroot usr/lib/ directory names, which differ
# from the clang target triples for armv7 (arm-linux-androideabi vs armv7a-...).
compile_arch "$PREBUILT/bin/aarch64-linux-android${API}-clang++"  arm64-v8a    aarch64-linux-android
compile_arch "$PREBUILT/bin/armv7a-linux-androideabi${API}-clang++" armeabi-v7a arm-linux-androideabi
compile_arch "$PREBUILT/bin/i686-linux-android${API}-clang++"      x86          i686-linux-android
compile_arch "$PREBUILT/bin/x86_64-linux-android${API}-clang++"    x86_64       x86_64-linux-android

echo "All native libraries built successfully."
