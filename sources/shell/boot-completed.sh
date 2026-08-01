#!/system/bin/sh
# boot-completed.sh v1.1
MODDIR=${0%/*}
DATA_DIR="/data/adb/stealth_ultimate"
CACHE_DIR="/cache/stealth_ultimate"

mkdir -p "$DATA_DIR" "$CACHE_DIR" 2>/dev/null

# Mark boot as completed — this resets the bootloop counter
touch "$DATA_DIR/boot_completed"
echo "0" > "/cache/stealth_boot_flag" 2>/dev/null

# Ensure config exists
if [ ! -f "$DATA_DIR/stealth.conf" ]; then
    cp "$MODDIR/common/stealth.conf.default" "$DATA_DIR/stealth.conf" 2>/dev/null
fi
cp "$DATA_DIR/stealth.conf" "$CACHE_DIR/stealth.conf" 2>/dev/null
chmod 644 "$DATA_DIR/stealth.conf" "$CACHE_DIR/stealth.conf" 2>/dev/null
