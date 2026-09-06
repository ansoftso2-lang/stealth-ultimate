#!/usr/bin/env bash
# Cross-compile the Zygisk library for every Android ABI via ndk-build.
#
# This mirrors the upstream zygisk-module-sample build process, which is the
# only configuration guaranteed to be compatible with the Zygisk loader in
# zygote: APP_STL=none, -fno-exceptions -fno-rtti, no libc++_shared.so.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JNIDIR="$SCRIPT_DIR/zygisk"
OUT_DIR="$SCRIPT_DIR/zygisk"
NDK="${NDK_HOME:-${ANDROID_NDK_HOME:-}}"

[[ -f "$JNIDIR/stealth_ultimate.cpp" ]] || { echo "Source not found: $JNIDIR/stealth_ultimate.cpp" >&2; exit 1; }
[[ -f "$JNIDIR/Android.mk" ]]           || { echo "Android.mk not found" >&2; exit 1; }
[[ -f "$JNIDIR/Application.mk" ]]       || { echo "Application.mk not found" >&2; exit 1; }
[[ -n "$NDK" && -d "$NDK" ]]            || { echo "Android NDK not found. Set NDK_HOME." >&2; exit 1; }

NDK_BUILD="$(find "$NDK" -maxdepth 1 -name ndk-build -print -quit)"
[[ -n "$NDK_BUILD" && -x "$NDK_BUILD" ]] || {
    # On Windows hosts ndk-build is a .cmd/.bat
    NDK_BUILD="$(find "$NDK" -maxdepth 1 \( -name 'ndk-build.cmd' -o -name 'ndk-build.bat' \) -print -quit)"
    [[ -n "$NDK_BUILD" ]] || { echo "ndk-build not found in: $NDK" >&2; exit 1; }
}

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "Building with: $NDK_BUILD"
"$NDK_BUILD" \
    NDK_PROJECT_PATH="$BUILD_DIR" \
    APP_BUILD_SCRIPT="$JNIDIR/Android.mk" \
    NDK_APPLICATION_MK="$JNIDIR/Application.mk" \
    APP_PLATFORM=android-21 \
    APP_STL=none \
    V=1

# ndk-build outputs to <BUILD>/local/<abi>/libstealth.so
ABIS=(arm64-v8a armeabi-v7a x86 x86_64)
rm -f "$OUT_DIR"/*.so
for abi in "${ABIS[@]}"; do
    src="$BUILD_DIR/local/$abi/libstealth.so"
    if [[ ! -s "$src" ]]; then
        echo "Missing or empty build output: $src" >&2
        exit 1
    fi
    cp "$src" "$OUT_DIR/$abi.so"
    echo "  $abi.so -> $(ls -lh "$OUT_DIR/$abi.so" | awk '{print $5}')"
done

echo "All native libraries built successfully."
