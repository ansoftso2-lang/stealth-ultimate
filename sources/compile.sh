#!/usr/bin/env bash
# Cross-compile the Zygisk library for every Android ABI.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/zygisk/stealth_ultimate.cpp"
OUT_DIR="$SCRIPT_DIR/zygisk"
NDK="${NDK_HOME:-${ANDROID_NDK_HOME:-}}"
API=24

# The official zygisk.hpp is a local header in the same folder as the source.
INCLUDE_FLAGS=(-I"$SCRIPT_DIR/zygisk")

[[ -f "$SRC" ]] || { echo "Source file not found: $SRC" >&2; exit 1; }
[[ -n "$NDK" && -d "$NDK" ]] || { echo "Android NDK not found. Set NDK_HOME." >&2; exit 1; }

PREBUILT="$(find "$NDK/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ -n "$PREBUILT" && -d "$PREBUILT/bin" ]] || {
    echo "NDK LLVM toolchain not found under: $NDK" >&2
    exit 1
}

COMMON_FLAGS=(
    -O2
    -fPIC
    -shared
    -std=c++17
    -Wall
    -Wextra
    -Wl,--hash-style=both
    -Wl,-z,global
    -Wl,-z,now
    -Wl,-z,noexecstack
)
LIBS=(-lc -ldl)

compile_arch() {
    local compiler="$1"
    local abi="$2"
    local output="$OUT_DIR/$abi.so"

    [[ -x "$compiler" ]] || { echo "Compiler not found: $compiler" >&2; exit 1; }
    echo "Compiling $abi with $(basename "$compiler")..."
    "$compiler" "${INCLUDE_FLAGS[@]}" "${COMMON_FLAGS[@]}" -o "$output" "$SRC" "${LIBS[@]}"
    [[ -s "$output" ]] || { echo "Compiler produced no output: $output" >&2; exit 1; }
    file "$output"
    ls -lh "$output"
}

rm -f "$OUT_DIR"/*.so
compile_arch "$PREBUILT/bin/aarch64-linux-android${API}-clang" arm64-v8a
compile_arch "$PREBUILT/bin/armv7a-linux-androideabi${API}-clang" armeabi-v7a
compile_arch "$PREBUILT/bin/i686-linux-android${API}-clang" x86
compile_arch "$PREBUILT/bin/x86_64-linux-android${API}-clang" x86_64

echo "All native libraries built successfully."
