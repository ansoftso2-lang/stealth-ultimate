#!/bin/bash
# compile.sh v2.0 — Cross-compile Zygisk module for all Android arches
# Requires: Android NDK
# Usage: export NDK_HOME=/path/to/android-ndk && ./compile.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/zygisk/stealth_ultimate.c"
OUT_DIR="$SCRIPT_DIR/zygisk"

NDK="${NDK_HOME:-${ANDROID_NDK_HOME:-/opt/android-ndk}}"
API=24

CFLAGS="-O2 -fPIC -shared \
    -Wl,--hash-style=both \
    -Wl,-z,global \
    -Wl,-z,now \
    -Wl,-z,noexecstack \
    -Wall -Wextra"

LIBS="-lc -ldl"

compile_arch() {
    local cc="$1"
    local arch="$2"
    local out="$OUT_DIR/$arch.so"
    echo "Compiling for $arch..."
    if command -v "$cc" &>/dev/null; then
        "$cc" $CFLAGS -o "$out" "$SRC" $LIBS
        echo "  ✓ $out ($(du -h "$out" | cut -f1))"
    else
        echo "  ✗ $cc not found, skipping $arch"
    fi
}

if [ -d "$NDK" ]; then
    PREBUILT=$(ls -d "$NDK"/toolchains/llvm/prebuilt/* 2>/dev/null | head -1)
    if [ -n "$PREBUILT" ]; then
        echo "Using NDK: $NDK"
        compile_arch "$PREBUILT/bin/aarch64-linux-android${API}-clang" "arm64-v8a" &
        compile_arch "$PREBUILT/bin/armv7a-linux-androideabi${API}-clang" "armeabi-v7a" &
        compile_arch "$PREBUILT/bin/i686-linux-android${API}-clang" "x86" &
        compile_arch "$PREBUILT/bin/x86_64-linux-android${API}-clang" "x86_64" &
        wait
    else
        echo "NDK found but no prebuilt toolchain"
        exit 1
    fi
else
    echo "NDK not found at $NDK, trying PATH..."
    compile_arch "${CC_arm64:-aarch64-linux-android24-clang}" "arm64-v8a" &
    compile_arch "${CC_arm:-armv7a-linux-androideabi24-clang}" "armeabi-v7a" &
    compile_arch "${CC_x86:-i686-linux-android24-clang}" "x86" &
    compile_arch "${CC_x86_64:-x86_64-linux-android24-clang}" "x86_64" &
    wait
fi

echo ""
echo "=== Compilation complete ==="
ls -lh "$OUT_DIR"/*.so 2>/dev/null || echo "No .so files found."
