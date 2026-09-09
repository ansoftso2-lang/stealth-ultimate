#!/system/bin/sh
# post-fs-data.sh v8.0 — Maximum hiding with bootloop protection
# All operations are best-effort: if any fails, boot continues normally.
# Safety-first approach: no operation can cause a bootloop.
MODDIR=${0%/*}
DATA_DIR="/data/adb/su_stealth"

mkdir -p "$DATA_DIR" 2>/dev/null
[ -f "$DATA_DIR/spoof.conf" ] || \
    cp "$MODDIR/common/stealth.conf.default" "$DATA_DIR/spoof.conf" 2>/dev/null
chmod 644 "$DATA_DIR/spoof.conf" 2>/dev/null

LOG="$DATA_DIR/stealth_boot.log"
log() { echo "$(date '+%H:%M:%S') [boot] $1" >> "$LOG" 2>/dev/null; }

log "=== post-fs-data.sh v8.0 starting ==="

# ── Bootloop protection: limit log size ──
if [ -f "$LOG" ]; then
    LOGSIZE=$(stat -c%s "$LOG" 2>/dev/null || echo 0)
    if [ "$LOGSIZE" -gt 102400 ]; then
        : > "$LOG"
        log "=== log rotated ==="
    fi
fi

# ── 1. SELinux enforce (best-effort, no force) ──
ENF=/sys/fs/selinux/enforce
if [ -w "$ENF" ]; then
    cur=$(cat "$ENF" 2>/dev/null)
    [ "$cur" != "1" ] && echo 1 > "$ENF" 2>/dev/null
    log "SELinux enforce set to 1"
fi

# ── 2. SELinux policy patches (safe, with timeout) ──
MAGISKPOLICY="/data/adb/magisk/magiskpolicy"
[ -x "$MAGISKPOLICY" ] || MAGISKPOLICY="/system/bin/magiskpolicy"
[ -x "$MAGISKPOLICY" ] || MAGISKPOLICY=$(which magiskpolicy 2>/dev/null)

if [ -x "$MAGISKPOLICY" ]; then
    # Keymaster HAL access (with 5s timeout to prevent boot hang)
    timeout 5 $MAGISKPOLICY --live "allow * hal_keymaster_default:binder call" 2>/dev/null
    timeout 5 $MAGISKPOLICY --live "allow * hal_keymaster_default:binder transfer" 2>/dev/null
    timeout 5 $MAGISKPOLICY --live "allow * hal_keymaster_default:fd use" 2>/dev/null
    timeout 5 $MAGISKPOLICY --live "allow * keystore_service:binder call" 2>/dev/null
    timeout 5 $MAGISKPOLICY --live "allow * keystore_service:fd use" 2>/dev/null
    timeout 5 $MAGISKPOLICY --live "allow root proc_keymaster:file rw" 2>/dev/null
    timeout 5 $MAGISKPOLICY --live "allow root proc_keymaster:dir search" 2>/dev/null
    timeout 5 $MAGISKPOLICY --live "allow root proc_bootconfig:file r" 2>/dev/null
    timeout 5 $MAGISKPOLICY --live "allow root proc_cmdline:file r" 2>/dev/null
    # v8.0: additional safe policies for attestation
    timeout 5 $MAGISKPOLICY --live "allow * hal_keymint_default:binder call" 2>/dev/null
    timeout 5 $MAGISKPOLICY --live "allow * hal_keymint_default:binder transfer" 2>/dev/null
    timeout 5 $MAGISKPOLICY --live "allow * hal_keymint_default:fd use" 2>/dev/null
    log "SELinux policy patched for keymaster/keymint + verified boot"
else
    log "WARNING: magiskpolicy not found — SELinux patches skipped (safe)"
fi

# ── 3. Global property spoofing via resetprop --late ──
resetprop_late() {
    if [ -x /data/adb/magisk/magisk ]; then
        /data/adb/magisk/magisk --resetprop --late "$1" "$2" 2>/dev/null
    elif command -v resetprop >/dev/null 2>&1; then
        resetprop --late "$1" "$2" 2>/dev/null
    fi
}

# Build identity (Pixel 6a / bluejay)
resetprop_late ro.build.fingerprint "google/bluejay/bluejay:14/UD1A.240105.004/11207768:user/release-keys"
resetprop_late ro.bootimage.build.fingerprint "google/bluejay/bluejay:14/UD1A.240105.004/11207768:user/release-keys"
resetprop_late ro.build.description "google/bluejay/bluejay:14/UD1A.240105.004/11207768:user/release-keys"
resetprop_late ro.build.display.id "UD1A.240105.004"
resetprop_late ro.build.id "UD1A.240105.004"
resetprop_late ro.build.version.incremental "11207768"
resetprop_late ro.build.version.security_patch "2024-01-05"
resetprop_late ro.build.version.release "14"
resetprop_late ro.build.version.sdk "34"
resetprop_late ro.build.type "user"
resetprop_late ro.build.tags "release-keys"
resetprop_late ro.build.selinux "1"
resetprop_late ro.build.characteristics "nosdcard"

# Product
resetprop_late ro.product.brand "google"
resetprop_late ro.product.manufacturer "Google"
resetprop_late ro.product.model "Pixel 6a"
resetprop_late ro.product.device "bluejay"
resetprop_late ro.product.name "bluejay"
resetprop_late ro.product.board "bluejay"
resetprop_late ro.board.platform "bluejay"
resetprop_late ro.hardware "bluejay"
resetprop_late ro.bootloader "bluejay-1.0-1068493"
resetprop_late ro.boot.bootloader "bluejay-1.0-1068493"

# Bootloader / verified boot
resetprop_late ro.boot.verifiedbootstate "green"
resetprop_late ro.boot.flash.locked "1"
resetprop_late ro.boot.veritymode "enforcing"
resetprop_late ro.boot.vbmeta.device_state "locked"
resetprop_late ro.boot.warranty_bit "0"
resetprop_late ro.warranty_bit "0"
resetprop_late ro.boot.oem_unlock_supported "0"
resetprop_late ro.oem_unlock_supported "0"
resetprop_late ro.boot.keymaster "1"
resetprop_late ro.debuggable "0"
resetprop_late ro.secure "1"
resetprop_late ro.bootmode "normal"
resetprop_late ro.boot.bootreason "reboot"

# Hide Zygisk native bridge
resetprop_late ro.dalvik.vm.native.bridge "0"

# Serial
resetprop_late ro.boot.serialno "RF5C1234ABCD"
resetprop_late ro.serialno "RF5C1234ABCD"

# ABI
resetprop_late ro.product.cpu.abi "arm64-v8a"
resetprop_late ro.product.cpu.abilist "arm64-v8a,armeabi-v7a,armeabi"
resetprop_late ro.product.cpu.abilist32 "armeabi-v7a,armeabi"
resetprop_late ro.product.cpu.abilist64 "arm64-v8a"

# Baseband
resetprop_late ro.baseband "g5300q-240105-240111-B-11207768"
resetprop_late ro.boot.baseband "g5300q-240105-240111-B-11207768"
resetprop_late ro.gsm.version.baseband "g5300q-240105-240111-B-11207768"

# v8.0: Additional product props for consistency
resetprop_late ro.product.vendor.name "bluejay"
resetprop_late ro.product.vendor.device "bluejay"
resetprop_late ro.product.vendor.brand "google"
resetprop_late ro.product.vendor.manufacturer "Google"
resetprop_late ro.product.vendor.model "Pixel 6a"
resetprop_late ro.product.system.name "bluejay"
resetprop_late ro.product.system.device "bluejay"
resetprop_late ro.product.system.brand "google"
resetprop_late ro.product.odm.name "bluejay"
resetprop_late ro.product.odm.device "bluejay"
resetprop_late ro.crypto.state "encrypted"
resetprop_late ro.crypto.type "block"
resetprop_late ro.build.date.utc "1704067200"

# Clear root manager traces
resetprop_late ro.magisk.version ""
resetprop_late ro.magisk.versionCode ""
resetprop_late ro.kernelsu.version ""
resetprop_late ro.kernelsu.version_code ""
resetprop_late ro.apatch.version ""
resetprop_late init.svc.magisk_pfsd ""
resetprop_late init.svc.magisk_pfs ""
resetprop_late persist.sys.magisk ""
resetprop_late persist.sys.pixelprops.api ""
resetprop_late persist.sys.pixelprops.gms ""
resetprop_late persist.sys.pixelprops.com ""
resetprop_late persist.sys.pixelprops.retail ""

# v8.0: Clear additional detection props
resetprop_late ro.boot.vbmeta.hash_alg "sha256"
resetprop_late ro.boot.vbmeta.size "0x1000"
resetprop_late ro.boot.vbmeta.digest "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
resetprop_late persist.magisk.log "0"
resetprop_late persist.magisk.verbose "0"
resetprop_late ro.revision "0"
resetprop_late ro.product.first_api_level "32"
resetprop_late ro.boot.hardware "bluejay"
resetprop_late ro.boot.hardware.sku "bluejay"

log "Global properties spoofed via resetprop --late"

# ── 4. /proc/cmdline patching (best-effort) ──
if [ -w "/proc/cmdline" ] 2>/dev/null; then
    CUR=$(cat /proc/cmdline 2>/dev/null)
    if echo "$CUR" | grep -q "verifiedbootstate=orange\|verifiedbootstate=yellow\|flash.locked=0\|vbmeta.device_state=unlocked"; then
        NEW=$(echo "$CUR" | \
            sed 's/verifiedbootstate=orange/verifiedbootstate=green/g' | \
            sed 's/verifiedbootstate=yellow/verifiedbootstate=green/g' | \
            sed 's/flash.locked=0/flash.locked=1/g' | \
            sed 's/vbmeta.device_state=unlocked/vbmeta.device_state=locked/g' | \
            sed 's/warranty_bit=1/warranty_bit=0/g')
        echo "$NEW" > /proc/cmdline 2>/dev/null && log "cmdline patched" || log "cmdline write failed (expected)"
    fi
else
    log "/proc/cmdline not writable (expected) — Zygisk hook handles this in-process"
fi

log "=== post-fs-data.sh v8.0 complete ==="

# ── 5. Auto-add root detection apps to Magisk DenyList ──
# Zygisk ONLY injects modules into processes on the denylist.
# Without this, our module never loads in the target app → nothing is hidden.
# Native Detector package: com.drsniffer.detector (Dr-TSNG/NativeDetector)
DENY_PKGS="com.drsniffer.detector io.github.vvb2060.magiskdetector"
if [ -x /data/adb/magisk/magisk ]; then
    for pkg in $DENY_PKGS; do
        # Check if package is installed before adding
        if pm list packages 2>/dev/null | grep -q "$pkg"; then
            magisk --denylist add "$pkg" 2>/dev/null
            log "denylist: added $pkg"
        fi
    done
    # Also add any installed package with "detector" in the name
    for pkg in $(pm list packages 2>/dev/null | grep -i 'detect\|root\|magisk\|checker' | sed 's/package://' | cut -d: -f1); do
        magisk --denylist add "$pkg" 2>/dev/null
        log "denylist: auto-added $pkg"
    done
    log "denylist auto-add complete"
fi
