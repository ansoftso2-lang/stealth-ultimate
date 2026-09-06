#!/system/bin/sh
# post-fs-data.sh v3.0 — Early boot: create runtime dir + config copy.
MODDIR=${0%/*}
DATA_DIR="/data/adb/su_stealth"

mkdir -p "$DATA_DIR" 2>/dev/null
[ -f "$DATA_DIR/spoof.conf" ] || \
    cp "$MODDIR/common/stealth.conf.default" "$DATA_DIR/spoof.conf" 2>/dev/null
chmod 644 "$DATA_DIR/spoof.conf" 2>/dev/null

# Try to hide SELinux permissive traces if present (best-effort; never force).
# Many detectors read /sys/fs/selinux/enforce expecting "1".
ENF=/sys/fs/selinux/enforce
if [ -w "$ENF" ]; then
    cur=$(cat "$ENF" 2>/dev/null)
    [ "$cur" != "1" ] && echo 1 > "$ENF" 2>/dev/null || true
fi
