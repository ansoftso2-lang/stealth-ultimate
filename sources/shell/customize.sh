#!/system/bin/sh
# customize.sh v6.0 — Universal installer + auto-install companion modules
SKIPUNZIP=0

DATA_DIR="/data/adb/su_stealth"

ui_print " ================================"
ui_print "  Stealth Ultimate v6.0"
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

# Zygisk check
ZYGIK_OK=0
if [ "$ROOT_FW" = "magisk" ]; then
    if [ "$ZYGISK_ENABLED" = "1" ]; then
        ZYGIK_OK=1
        ui_print "- Zygisk: enabled"
    else
        ui_print "  ! Zygisk disabled in Magisk settings"
    fi
else
    if [ -d "/data/adb/modules/zygisksu" ] || [ -d "/data/adb/modules/zygisk_next" ] || \
       [ -d "/data/adb/modules/rezygisk" ]; then
        ZYGIK_OK=1
        ui_print "- Zygisk loader detected"
    else
        ui_print "  ! No Zygisk loader found"
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

# ── Auto-install companion modules for 100% hiding ──
ui_print ""
ui_print "- Checking companion modules..."

# Helper: download and install a module zip
install_module() {
    local name="$1"
    local url="$2"
    local tmpzip="/data/local/tmp/${name}.zip"

    if [ -d "/data/adb/modules/$name" ]; then
        ui_print "  = $name already installed, skipping"
        return 0
    fi

    ui_print "  + Downloading $name..."
    if command -v curl >/dev/null 2>&1; then
        curl -sL "$url" -o "$tmpzip" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$tmpzip" 2>/dev/null
    else
        ui_print "  ! No curl/wget, skipping $name"
        return 1
    fi

    if [ -f "$tmpzip" ] && [ $(stat -c%s "$tmpzip" 2>/dev/null || echo 0) -gt 1000 ]; then
        ui_print "  + Installing $name..."
        if [ "$ROOT_FW" = "magisk" ] && command -v magisk >/dev/null 2>&1; then
            magisk --install-module "$tmpzip" 2>/dev/null
        else
            # Manual install: extract to /data/adb/modules/
            mkdir -p "/data/adb/modules/$name" 2>/dev/null
            cd "/data/adb/modules/$name" && unzip -o "$tmpzip" 2>/dev/null
            cd /
        fi
        rm -f "$tmpzip"
        ui_print "  + $name installed"
    else
        ui_print "  ! Failed to download $name"
        rm -f "$tmpzip"
        return 1
    fi
    return 0
}

# Shamiko — hides Zygisk ptrace + mount namespace + process traces
SHAMIKO_URL="https://github.com/LSPosed/LSPosed.github.io/releases/download/shamiko-2.4.0-2/zygisk-shamiko-v2.4.0-2-release.zip"
install_module "zygisk_shamiko" "$SHAMIKO_URL"

# PlayIntegrityFix — spoofs Play Integrity verdicts
PIF_URL="https://github.com/chiteraDocs/PlayIntegrityFix/releases/latest/download/PlayIntegrityFix.zip"
install_module "playintegrityfix" "$PIF_URL"

# TrickyStore — hardware key attestation spoofing
TS_URL="https://github.com/5ec1cff/TrickyStore/releases/latest/download/TrickyStore.zip"
install_module "tricky_store" "$TS_URL"

ui_print ""
ui_print " ================================"
ui_print "  Installation complete."
ui_print "  Companion modules installed:"
ui_print "  - Shamiko (Zygisk hiding)"
ui_print "  - PlayIntegrityFix (PI)"
ui_print "  - TrickyStore (key attestation)"
ui_print "  Reboot to activate all."
ui_print " ================================"
