#!/system/bin/sh
# post-fs-data.sh v2.2 — Early boot: create runtime dirs + config copy.
MODDIR=${0%/*}
DATA_DIR="/data/adb/stealth_ultimate"

mkdir -p "$DATA_DIR" 2>/dev/null
[ -f "$DATA_DIR/stealth.conf" ] || \
    cp "$MODDIR/common/stealth.conf.default" "$DATA_DIR/stealth.conf" 2>/dev/null
chmod 644 "$DATA_DIR/stealth.conf" 2>/dev/null
