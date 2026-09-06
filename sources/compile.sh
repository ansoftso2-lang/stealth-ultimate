#!/usr/bin/env bash
# Cross-compile the Zygisk library for every Android ABI via ndk-build.
#
# ndk-build is the only build path that correctly resolves APP_STL=c++_static
# (static libc++, no libc++_shared.so dependency). Direct clang++ cannot do
# this reliably because NDK r27b defaults to libc++_shared.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JNIDIR="$SCRIPT_DIR/zygisk"
OUT_DIR="$SCRIPT_DIR/zygisk"
NDK="${NDK_HOME:-${ANDROID_NDK_HOME:-}}"

[[ -f "$JNIDIR/stealth_ultimate.cpp" ]] || { echo "Source not found" >&2; exit 1; }
[[ -f "$JNIDIR/Android.mk" ]]           || { echo "Android.mk not found" >&2; exit 1; }
[[ -f "$JNIDIR/Application.mk" ]]       || { echo "Application.mk not found" >&2; exit 1; }
[[ -n "$NDK" && -d "$NDK" ]]            || { echo "Android NDK not found. Set NDK_HOME." >&2; exit 1; }

NDK_BUILD="$(find "$NDK" -maxdepth 1 -name ndk-build -print -quit)"
[[ -n "$NDK_BUILD" && -x "$NDK_BUILD" ]] || {
    NDK_BUILD="$(find "$NDK" -maxdepth 1 \( -name 'ndk-build.cmd' -o -name 'ndk-build.bat' \) -print -quit)"
    [[ -n "$NDK_BUILD" ]] || { echo "ndk-build not found in: $NDK" >&2; exit 1; }
}

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

# ndk-build discovers jni/Android.mk and jni/Application.mk relative to
# NDK_PROJECT_PATH. Set up the standard layout so APP_STL etc. are honored.
mkdir -p "$BUILD_DIR/jni"
cp "$JNIDIR/Android.mk"     "$BUILD_DIR/jni/Android.mk"
cp "$JNIDIR/Application.mk" "$BUILD_DIR/jni/Application.mk"
cp "$JNIDIR/stealth_ultimate.cpp" "$BUILD_DIR/jni/stealth_ultimate.cpp"
cp "$JNIDIR/zygisk.hpp"     "$BUILD_DIR/jni/zygisk.hpp"

echo "Building with: $NDK_BUILD"
"$NDK_BUILD" \
    NDK_PROJECT_PATH="$BUILD_DIR" \
    V=1

# ndk-build outputs to <BUILD>/libs/<abi>/libstealth.so
ABIS=(arm64-v8a armeabi-v7a x86 x86_64)
rm -f "$OUT_DIR"/*.so
for abi in "${ABIS[@]}"; do
    src="$BUILD_DIR/libs/$abi/libstealth.so"
    if [[ ! -s "$src" ]]; then
        echo "Missing or empty build output: $src" >&2
        exit 1
    fi
    cp "$src" "$OUT_DIR/$abi.so"
    echo "  $abi.so -> $(ls -lh "$OUT_DIR/$abi.so" | awk '{print $5}')"
done

echo "All native libraries built successfully."
