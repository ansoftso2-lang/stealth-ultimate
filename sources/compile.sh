#!/usr/bin/env bash
# Cross-compile the Zygisk library for every Android ABI.
#
# Simple direct clang++ invocation. libc++_shared.so is a system library
# present in /system/lib* and available in zygote, so depending on it is fine.
# The earlier "incompatibility" was caused by ZYGISK_API_VERSION mismatch
# (v4 vs v5), not by libc++_shared.so.

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
    -Wl,-u,zygisk_module_entry
    -Wl,-u,zygisk_companion_entry
    -Wl,--export-dynamic
)
LIBS=(-lc -ldl -llog)

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
compile_arch "$PREBUILT/bin/aarch64-linux-android${API}-clang++" arm64-v8a
compile_arch "$PREBUILT/bin/armv7a-linux-androideabi${API}-clang++" armeabi-v7a
compile_arch "$PREBUILT/bin/i686-linux-android${API}-clang++" x86
compile_arch "$PREBUILT/bin/x86_64-linux-android${API}-clang++" x86_64

echo "All native libraries built successfully."
