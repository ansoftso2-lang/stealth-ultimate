#!/system/bin/sh
# post-fs-data.sh v1.1 — Early boot: copy config, get root UIDs
MODDIR=${0%/*}
DATA_DIR="/data/adb/stealth_ultimate"
CACHE_DIR="/cache/stealth_ultimate"

mkdir -p "$DATA_DIR" "$CACHE_DIR" 2>/dev/null

# Remove any stale disable files — never auto-disable
rm -f "$DATA_DIR/disable" "$CACHE_DIR/disable" "/cache/stealth_bootloop" "/cache/stealth_boot_flag" 2>/dev/null

# Copy default config if not present
if [ ! -f "$DATA_DIR/stealth.conf" ]; then
    cp "$MODDIR/common/stealth.conf.default" "$DATA_DIR/stealth.conf" 2>/dev/null
fi
cp "$DATA_DIR/stealth.conf" "$CACHE_DIR/stealth.conf" 2>/dev/null
chmod 644 "$DATA_DIR/stealth.conf" "$CACHE_DIR/stealth.conf" 2>/dev/null

# ── Get root-granted UIDs from root manager databases ──
ROOT_UIDS=""

# Magisk: policies table (Magisk 25+)
if command -v magisk >/dev/null 2>&1; then
    ROOT_UIDS=$(magisk --sqlite "SELECT uid FROM policies WHERE policy=2" 2>/dev/null | grep -oE '[0-9]+$')
    if [ -z "$ROOT_UIDS" ]; then
        ROOT_UIDS=$(magisk --sqlite "SELECT uid FROM uids WHERE policy=2" 2>/dev/null | grep -oE '[0-9]+$')
    fi
fi

# Try sqlite3 directly on Magisk DB
if [ -z "$ROOT_UIDS" ] && [ -f /data/adb/magisk.db ]; then
    if command -v sqlite3 >/dev/null 2>&1; then
        ROOT_UIDS=$(sqlite3 /data/adb/magisk.db "SELECT uid FROM policies WHERE policy=2" 2>/dev/null)
        if [ -z "$ROOT_UIDS" ]; then
            ROOT_UIDS=$(sqlite3 /data/adb/magisk.db "SELECT uid FROM uids WHERE policy=2" 2>/dev/null)
        fi
    fi
fi

# KernelSU
if [ -z "$ROOT_UIDS" ] && command -v ksud >/dev/null 2>&1; then
    ROOT_UIDS=$(ksud sqlite "SELECT uid FROM root_config WHERE policy=2" 2>/dev/null | grep -oE '[0-9]+$')
fi
if [ -z "$ROOT_UIDS" ] && [ -f /data/adb/ksu/db.db ]; then
    if command -v sqlite3 >/dev/null 2>&1; then
        ROOT_UIDS=$(sqlite3 /data/adb/ksu/db.db "SELECT uid FROM root_config WHERE policy=2" 2>/dev/null)
    fi
fi

# APatch
if [ -z "$ROOT_UIDS" ] && command -v apd >/dev/null 2>&1; then
    ROOT_UIDS=$(apd sqlite "SELECT uid FROM root_config WHERE policy=2" 2>/dev/null | grep -oE '[0-9]+$')
fi
if [ -z "$ROOT_UIDS" ] && [ -f /data/adb/apatch/db.db ]; then
    if command -v sqlite3 >/dev/null 2>&1; then
        ROOT_UIDS=$(sqlite3 /data/adb/apatch/db.db "SELECT uid FROM root_config WHERE policy=2" 2>/dev/null)
    fi
fi

# Write root UIDs file
if [ -n "$ROOT_UIDS" ]; then
    echo "$ROOT_UIDS" > "$DATA_DIR/root_uids.txt" 2>/dev/null
    echo "$ROOT_UIDS" > "$CACHE_DIR/root_uids.txt" 2>/dev/null
    chmod 644 "$DATA_DIR/root_uids.txt" "$CACHE_DIR/root_uids.txt" 2>/dev/null
else
    : > "$DATA_DIR/root_uids.txt" 2>/dev/null
    : > "$CACHE_DIR/root_uids.txt" 2>/dev/null
fi

# ── Smart bootloop protection ──
# Only counts REAL bootloops: consecutive boots where boot-completed never ran.
# Normal reboots never trigger it because boot-completed.sh clears the flag.
BOOT_FLAG="/cache/stealth_boot_flag"
COMPLETED_FLAG="/data/adb/stealth_ultimate/boot_completed"

# If boot-completed ran last time, the completed flag exists → reset counter
if [ -f "$COMPLETED_FLAG" ]; then
    rm -f "$BOOT_FLAG" "$COMPLETED_FLAG" 2>/dev/null
fi

# Count consecutive failed boots (where boot-completed didn't run)
COUNT=0
if [ -f "$BOOT_FLAG" ]; then
    COUNT=$(cat "$BOOT_FLAG" 2>/dev/null || echo 0)
fi
COUNT=$((COUNT + 1))
echo "$COUNT" > "$BOOT_FLAG" 2>/dev/null

# Only disable after 5 consecutive failed boots (real bootloop)
if [ "$COUNT" -ge 5 ]; then
    # Last resort: disable to recover the device
    touch "$MODDIR/disable"
    rm -f "$BOOT_FLAG" 2>/dev/null
fi
