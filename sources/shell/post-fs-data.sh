#!/system/bin/sh
# post-fs-data.sh v7.0 — Maximum hiding: global prop spoofing + SELinux patches
# + keymaster access + vbmeta hiding + boot state spoofing
MODDIR=${0%/*}
DATA_DIR="/data/adb/su_stealth"

mkdir -p "$DATA_DIR" 2>/dev/null
[ -f "$DATA_DIR/spoof.conf" ] || \
    cp "$MODDIR/common/stealth.conf.default" "$DATA_DIR/spoof.conf" 2>/dev/null
chmod 644 "$DATA_DIR/spoof.conf" 2>/dev/null

LOG="$DATA_DIR/stealth_boot.log"
log() { echo "$(date '+%H:%M:%S') [boot] $1" >> "$LOG" 2>/dev/null || true; }

log "=== post-fs-data.sh starting ==="

# ── 1. SELinux enforce ──
ENF=/sys/fs/selinux/enforce
if [ -w "$ENF" ]; then
    cur=$(cat "$ENF" 2>/dev/null)
    [ "$cur" != "1" ] && echo 1 > "$ENF" 2>/dev/null
    log "SELinux enforce set to 1"
fi

# ── 2. SELinux policy patches for keymaster access ──
MAGISKPOLICY="/data/adb/magisk/magiskpolicy"
[ -x "$MAGISKPOLICY" ] || MAGISKPOLICY="/system/bin/magiskpolicy"
[ -x "$MAGISKPOLICY" ] || MAGISKPOLICY=$(which magiskpolicy 2>/dev/null)

if [ -x "$MAGISKPOLICY" ]; then
    # Allow keymaster HAL access
    $MAGISKPOLICY --live "allow * hal_keymaster_default:binder call" 2>/dev/null
    $MAGISKPOLICY --live "allow * hal_keymaster_default:binder transfer" 2>/dev/null
    $MAGISKPOLICY --live "allow * hal_keymaster_default:fd use" 2>/dev/null
    # Allow keystore access
    $MAGISKPOLICY --live "allow * keystore_service:binder call" 2>/dev/null
    $MAGISKPOLICY --live "allow * keystore_service:fd use" 2>/dev/null
    # Allow root to access keymaster proc
    $MAGISKPOLICY --live "allow root proc_keymaster:file rw" 2>/dev/null
    $MAGISKPOLICY --live "allow root proc_keymaster:dir search" 2>/dev/null
    # Allow access to verified boot props
    $MAGISKPOLICY --live "allow root proc_bootconfig:file r" 2>/dev/null
    $MAGISKPOLICY --live "allow root proc_cmdline:file r" 2>/dev/null
    log "SELinux policy patched for keymaster + verified boot"
else
    log "WARNING: magiskpolicy not found — SELinux patches skipped"
fi

# ── 3. Global property spoofing via resetprop --late ──
resetprop_late() {
    if [ -x /data/adb/magisk/magisk ]; then
        /data/adb/magisk/magisk --resetprop --late "$1" "$2" 2>/dev/null
    elif command -v resetprop >/dev/null 2>&1; then
        resetprop --late "$1" "$2" 2>/dev/null
    fi
}

# Build identity
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

# Bootloader / verified boot (maximum effort)
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

# VBMeta props
resetprop_late ro.boot.vbmeta.hash_alg "sha256"
resetprop_late ro.boot.vbmeta.size "0x1000"
resetprop_late ro.boot.vbmeta.digest "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

log "Global properties spoofed via resetprop --late"

# ── 4. Patch /proc/cmdline (best-effort) ──
# This may fail — /proc/cmdline is usually read-only
# But try to modify the boot config if possible
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

# ── 5. Hide Magisk/ksu traces from /proc ──
# Remove Magisk env variables from init environ
for key in MAGISK_INJECTOR MAGISK_PROCESS MAGISK_TMP; do
    if [ -f "/proc/self/environ" ]; then
        : # Can't modify /proc/self/environ directly — Zygisk hook handles this
    fi
done

# ── 6. Try to access keymaster and patch attestation ──
# This is best-effort — without keybox we can only try to modify the
# attestation challenge response, not the keybox itself.
KEYMASTER_HALS=$(find /proc -name "keymaster" -type d 2>/dev/null)
if [ -n "$KEYMASTER_HALS" ]; then
    log "Keymaster HAL found: $KEYMASTER_HALS"
fi

# Try to set keystore properties that affect attestation
resetprop_late ro.boot.verifiedbootstate "green"
resetprop_late ro.boot.flash.locked "1"
resetprop_late ro.boot.vbmeta.device_state "locked"
resetprop_late ro.boot.veritymode "enforcing"

# ── 7. Disable Magisk verbose logging (reduces traces) ──
resetprop_late persist.magisk.log "0"
resetprop_late persist.magisk.verbose "0"

log "=== post-fs-data.sh complete ==="
