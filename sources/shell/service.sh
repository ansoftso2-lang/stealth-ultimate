#!/system/bin/sh
# service.sh v2.2 — Optional post-boot: refresh root UID list.
MODDIR=${0%/*}
DATA_DIR="/data/adb/stealth_ultimate"
LOG="$DATA_DIR/stealth.log"

mkdir -p "$DATA_DIR" 2>/dev/null

log() { echo "$(date '+%H:%M:%S') [svc] $1" >> "$LOG" 2>/dev/null || true; }

until [ "$(getprop sys.boot_completed)" = "1" ] 2>/dev/null; do
    sleep 2
done
log "Boot completed"

ROOT_UIDS=""
if command -v magisk >/dev/null 2>&1; then
    ROOT_UIDS=$(magisk --sqlite "SELECT uid FROM policies WHERE policy=2" 2>/dev/null | grep -oE '[0-9]+$' | tr '\n' ' ')
    [ -z "$ROOT_UIDS" ] && ROOT_UIDS=$(magisk --sqlite "SELECT uid FROM uids WHERE policy=2" 2>/dev/null | grep -oE '[0-9]+$' | tr '\n' ' ')
elif [ -f /data/adb/magisk.db ] && command -v sqlite3 >/dev/null 2>&1; then
    ROOT_UIDS=$(sqlite3 /data/adb/magisk.db "SELECT uid FROM policies WHERE policy=2" 2>/dev/null | tr '\n' ' ')
    [ -z "$ROOT_UIDS" ] && ROOT_UIDS=$(sqlite3 /data/adb/magisk.db "SELECT uid FROM uids WHERE policy=2" 2>/dev/null | tr '\n' ' ')
elif command -v ksud >/dev/null 2>&1; then
    ROOT_UIDS=$(ksud sqlite "SELECT uid FROM root_config WHERE policy=2" 2>/dev/null | grep -oE '[0-9]+$' | tr '\n' ' ')
elif command -v apd >/dev/null 2>&1; then
    ROOT_UIDS=$(apd sqlite "SELECT uid FROM root_config WHERE policy=2" 2>/dev/null | grep -oE '[0-9]+$' | tr '\n' ' ')
fi

if [ -n "$ROOT_UIDS" ]; then
    echo "$ROOT_UIDS" > "$DATA_DIR/root_uids.txt" 2>/dev/null
    chmod 644 "$DATA_DIR/root_uids.txt" 2>/dev/null
    log "Root UIDs: $ROOT_UIDS"
else
    log "No root UIDs found"
fi

log "=== service.sh END ==="
