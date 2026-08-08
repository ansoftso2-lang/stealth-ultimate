#!/system/bin/sh
# customize.sh v2.2 — Installation-time checks and config copy.
SKIPUNZIP=0

ui_print " ================================"
ui_print "  Stealth Ultimate v2.2"
ui_print "  Zygisk Anti-Detection"
ui_print " ================================"
ui_print ""

[ -z "$MAGISK_VER_CODE" ] && { ui_print "! Need Magisk 24+"; abort; }
ui_print "- Magisk: $MAGISK_VER_CODE"

[ "$ZYGISK_ENABLED" != "1" ] && { ui_print "  ! Zygisk DISABLED"; abort; } || ui_print "  ✓ Zygisk ENABLED"

ARCH=$(getprop ro.product.cpu.abi)
ui_print "- CPU ABI: $ARCH"

ui_print "- Installing..."
mkdir -p /data/adb/stealth_ultimate 2>/dev/null

SO_FOUND=0
for arch in arm64-v8a armeabi-v7a x86 x86_64; do
    if [ -f "$MODPATH/zygisk/$arch.so" ]; then
        ui_print "  ✓ $arch.so"
        SO_FOUND=1
    fi
done
[ "$SO_FOUND" = "0" ] && { ui_print "  ✗ No .so files!"; abort; }

[ ! -f "$DATA_DIR/stealth.conf" ] && \
    cp -f "$MODPATH/common/stealth.conf.default" "$DATA_DIR/stealth.conf" 2>/dev/null
chmod 644 "$DATA_DIR/stealth.conf" 2>/dev/null

set_perm_recursive "$MODPATH" 0 0 0755 0644

ui_print ""
ui_print " ================================"
ui_print "  Installation Complete!"
ui_print "  Reboot to activate."
ui_print " ================================"
