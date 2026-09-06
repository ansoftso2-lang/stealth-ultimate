#!/system/bin/sh
# post-fs-data.sh v5.0 — Early boot: global prop spoofing via resetprop.
MODDIR=${0%/*}
DATA_DIR="/data/adb/su_stealth"

mkdir -p "$DATA_DIR" 2>/dev/null
[ -f "$DATA_DIR/spoof.conf" ] || \
    cp "$MODDIR/common/stealth.conf.default" "$DATA_DIR/spoof.conf" 2>/dev/null
chmod 644 "$DATA_DIR/spoof.conf" 2>/dev/null

# SELinux enforce
ENF=/sys/fs/selinux/enforce
if [ -w "$ENF" ]; then
    cur=$(cat "$ENF" 2>/dev/null)
    [ "$cur" != "1" ] && echo 1 > "$ENF" 2>/dev/null || true
fi

# Global property spoofing via resetprop --late
# --late hides the resetprop modification from prop_serial detection
RP=$(which resetprop 2>/dev/null || echo /data/adb/magisk/magisk --resetprop 2>/dev/null)

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

# Hide Zygisk native bridge trace
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

# Clear root manager version props (hide resetprop traces)
resetprop_late ro.magisk.version ""
resetprop_late ro.magisk.versionCode ""
resetprop_late ro.kernelsu.version ""
resetprop_late ro.kernelsu.version_code ""
resetprop_late ro.apatch.version ""
resetprop_late init.svc.magisk_pfsd ""
resetprop_late init.svc.magisk_pfs ""
resetprop_late persist.sys.magisk ""
