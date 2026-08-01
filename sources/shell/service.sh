#!/system/bin/sh
# service.sh v1.1 — Post-boot: refresh root UIDs
MODDIR=${0%/*}
DATA_DIR="/data/adb/stealth_ultimate"
CACHE_DIR="/cache/stealth_ultimate"

mkdir -p "$DATA_DIR" "$CACHE_DIR" 2>/dev/null

# Wait for boot
until [ "$(getprop sys.boot_completed)" = "1" ] 2>/dev/null; do
    sleep 2
done

# Refresh root UIDs (apps may have been granted/denied root since last boot)
ROOT_UIDS=""
if command -v magisk >/dev/null 2>&1; then
    ROOT_UIDS=$(magisk --sqlite "SELECT uid FROM policies WHERE policy=2" 2>/dev/null | grep -oE '[0-9]+$')
    if [ -z "$ROOT_UIDS" ]; then
        ROOT_UIDS=$(magisk --sqlite "SELECT uid FROM uids WHERE policy=2" 2>/dev/null | grep -oE '[0-9]+$')
    fi
fi
if [ -z "$ROOT_UIDS" ] && [ -f /data/adb/magisk.db ] && command -v sqlite3 >/dev/null 2>&1; then
    ROOT_UIDS=$(sqlite3 /data/adb/magisk.db "SELECT uid FROM policies WHERE policy=2" 2>/dev/null)
    if [ -z "$ROOT_UIDS" ]; then
        ROOT_UIDS=$(sqlite3 /data/adb/magisk.db "SELECT uid FROM uids WHERE policy=2" 2>/dev/null)
    fi
fi
if [ -z "$ROOT_UIDS" ] && command -v ksud >/dev/null 2>&1; then
    ROOT_UIDS=$(ksud sqlite "SELECT uid FROM root_config WHERE policy=2" 2>/dev/null | grep -oE '[0-9]+$')
fi
if [ -z "$ROOT_UIDS" ] && [ -f /data/adb/ksu/db.db ] && command -v sqlite3 >/dev/null 2>&1; then
    ROOT_UIDS=$(sqlite3 /data/adb/ksu/db.db "SELECT uid FROM root_config WHERE policy=2" 2>/dev/null)
fi
if [ -z "$ROOT_UIDS" ] && command -v apd >/dev/null 2>&1; then
    ROOT_UIDS=$(apd sqlite "SELECT uid FROM root_config WHERE policy=2" 2>/dev/null | grep -oE '[0-9]+$')
fi

if [ -n "$ROOT_UIDS" ]; then
    echo "$ROOT_UIDS" > "$DATA_DIR/root_uids.txt" 2>/dev/null
    echo "$ROOT_UIDS" > "$CACHE_DIR/root_uids.txt" 2>/dev/null
    chmod 644 "$DATA_DIR/root_uids.txt" "$CACHE_DIR/root_uids.txt" 2>/dev/null
fi

# Ensure config is accessible
if [ ! -f "$DATA_DIR/stealth.conf" ]; then
    cp "$MODDIR/common/stealth.conf.default" "$DATA_DIR/stealth.conf" 2>/dev/null
fi
cp "$DATA_DIR/stealth.conf" "$CACHE_DIR/stealth.conf" 2>/dev/null
chmod 644 "$DATA_DIR/stealth.conf" "$CACHE_DIR/stealth.conf" 2>/dev/null
