#!/system/bin/sh
# customize.sh v1.3 — Installation script
SKIPUNZIP=0

ui_print " ================================"
ui_print "  Stealth Ultimate v1.3"
ui_print "  Zygisk Anti-Detection"
ui_print " ================================"
ui_print ""

[ -z "$MAGISK_VER_CODE" ] && { ui_print "! Need Magisk 24+"; abort; }
ui_print "- Magisk: $MAGISK_VER_CODE"

if [ "$ZYGISK_ENABLED" != "1" ]; then
    ui_print "  ! Zygisk DISABLED"
    ui_print "  ! Enable: Magisk Settings -> Zygisk -> Enable"
    abort
else
    ui_print "  ✓ Zygisk ENABLED"
fi

ARCH=$(getprop ro.product.cpu.abi)
ui_print "- CPU: $ARCH"

ui_print "- Installing..."
mkdir -p /data/adb/stealth_ultimate
mkdir -p /cache/stealth_ultimate

# Detect module path: try $MODPATH first, then fallback to script location
MOD_DIR="$MODPATH"
if [ -z "$MOD_DIR" ] || [ ! -d "$MOD_DIR" ]; then
    MOD_DIR="$(cd "$(dirname "$0")" && pwd)"
fi
ui_print "  Module path: $MOD_DIR"

# Copy config
cp "$MOD_DIR/common/stealth.conf.default" /data/adb/stealth_ultimate/stealth.conf 2>/dev/null
cp "$MOD_DIR/common/stealth.conf.default" /cache/stealth_ultimate/stealth.conf 2>/dev/null
chmod 644 /data/adb/stealth_ultimate/stealth.conf 2>/dev/null
chmod 644 /cache/stealth_ultimate/stealth.conf 2>/dev/null

# Check for .so files
SO_FOUND=0
for arch in arm64-v8a armeabi-v7a x86 x86_64; do
    if [ -f "$MOD_DIR/zygisk/$arch.so" ]; then
        ui_print "  ✓ $arch.so ($(du -h "$MOD_DIR/zygisk/$arch.so" | cut -f1))"
        SO_FOUND=1
    else
        ui_print "  ! $arch.so missing (expected: $MOD_DIR/zygisk/$arch.so)"
    fi
done

if [ "$SO_FOUND" = "0" ]; then
    ui_print "  ✗ No .so files found!"
    ui_print "  Trying alternative locations..."
    
    # Try alternative locations
    for alt in "/data/adb/modules/stealth_ultimate/zygisk" "$MODPATH/zygisk"; do
        if [ -d "$alt" ]; then
            ui_print "  Found zygisk dir: $alt"
            ls -la "$alt" 2>/dev/null | while read -r line; do
                ui_print "    $line"
            done
        fi
    done
    
    ui_print "  ✗ Installation FAILED — .so files not found"
    abort
fi

set_perm_recursive "$MOD_DIR" 0 0 0755 0644

ui_print ""
ui_print " ================================"
ui_print "  Installation Complete!"
ui_print "  Reboot to activate."
ui_print " ================================"
