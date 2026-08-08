#!/system/bin/sh
# customize.sh v2.2 — Installation-time checks and config copy.
SKIPUNZIP=0

DATA_DIR="/data/adb/stealth_ultimate"

ui_print " ================================"
ui_print "  Stealth Ultimate v2.2"
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
    ui_print "  + Zygisk ENABLED"
fi

ARCH=$(getprop ro.product.cpu.abi)
ui_print "- CPU ABI: $ARCH"

ui_print "- Installing..."
mkdir -p "$DATA_DIR" 2>/dev/null

SO_FOUND=0
for arch in arm64-v8a armeabi-v7a x86 x86_64; do
    if [ -f "$MODPATH/zygisk/$arch.so" ]; then
        ui_print "  + $arch.so"
        SO_FOUND=1
    fi
done

if [ "$SO_FOUND" = "0" ]; then
    ui_print "  ! No .so files!"
    abort
fi

if [ ! -f "$DATA_DIR/stealth.conf" ]; then
    cp "$MODPATH/common/stealth.conf.default" "$DATA_DIR/stealth.conf" 2>/dev/null
fi
chmod 644 "$DATA_DIR/stealth.conf" 2>/dev/null

set_perm_recursive "$MODPATH" 0 0 0755 0644

ui_print ""
ui_print " ================================"
ui_print "  Installation Complete!"
ui_print "  Reboot to activate."
ui_print " ================================"
