#!/system/bin/sh
# customize.sh v3.0 — Universal installer (Magisk, KernelSU, APatch)
SKIPUNZIP=0

# Use a neutral data dir to avoid leaking the module name into /data/adb.
DATA_DIR="/data/adb/su_stealth"

ui_print " ================================"
ui_print "  Stealth Ultimate v3.0"
ui_print "  Universal Zygisk Anti-Detection"
ui_print " ================================"
ui_print ""

# Detect root framework
ROOT_FW="unknown"
if [ -n "$MAGISK_VER_CODE" ]; then
    ROOT_FW="magisk"
    ui_print "- Magisk: $MAGISK_VER_CODE"
elif [ -n "$KSU" ] || command -v ksud >/dev/null 2>&1; then
    ROOT_FW="ksu"
    ui_print "- KernelSU detected"
elif [ -n "$APATCH" ] || command -v apd >/dev/null 2>&1; then
    ROOT_FW="apatch"
    ui_print "- APatch detected"
fi

# Zygisk presence check across frameworks.
# - Magisk: ZYGISK_ENABLED env var
# - KernelSU: needs ZygiskNext/ReZygisk module (check for its marker)
# - APatch: same as KSU
ZYGIK_OK=0
if [ "$ROOT_FW" = "magisk" ]; then
    if [ "$ZYGISK_ENABLED" = "1" ]; then
        ZYGIK_OK=1
        ui_print "- Zygisk: enabled"
    else
        ui_print "  ! Zygisk disabled in Magisk settings"
    fi
else
    # KSU/APatch: rely on a zygisk-compatible loader being installed.
    if [ -d "/data/adb/modules/zygisksu" ] || [ -d "/data/adb/modules/zygisk_next" ] || \
       [ -d "/data/adb/modules/rezygisk" ] || [ -d "/data/adb/zygiskd" ]; then
        ZYGIK_OK=1
        ui_print "- Zygisk loader detected"
    else
        ui_print "  ! No Zygisk loader found"
        ui_print "  ! Install ZygiskNext or ReZygisk for $ROOT_FW"
    fi
fi

if [ "$ZYGIK_OK" != "1" ]; then
    ui_print "  ! Aborting: Zygisk is required."
    abort
fi

ARCH=$(getprop ro.product.cpu.abi)
ui_print "- CPU ABI: $ARCH"

ui_print "- Installing native libraries..."
mkdir -p "$DATA_DIR" 2>/dev/null

SO_FOUND=0
for arch in arm64-v8a armeabi-v7a x86 x86_64; do
    if [ -f "$MODPATH/zygisk/$arch.so" ]; then
        ui_print "  + $arch.so"
        SO_FOUND=1
    fi
done
if [ "$SO_FOUND" = "0" ]; then
    ui_print "  ! No native libraries found!"
    abort
fi

if [ ! -f "$DATA_DIR/spoof.conf" ]; then
    cp "$MODPATH/common/stealth.conf.default" "$DATA_DIR/spoof.conf" 2>/dev/null
fi
chmod 644 "$DATA_DIR/spoof.conf" 2>/dev/null

set_perm_recursive "$MODPATH" 0 0 0755 0644

ui_print ""
ui_print " ================================"
ui_print "  Installation complete."
ui_print "  Reboot to activate."
ui_print " ================================"
