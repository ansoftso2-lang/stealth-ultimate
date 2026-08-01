#!/system/bin/sh
# service.sh v1.3 — Post-boot: refresh root UIDs + configure Zygisk denylist
MODDIR=${0%/*}
DATA_DIR="/data/adb/stealth_ultimate"
CACHE_DIR="/cache/stealth_ultimate"
LOG="$DATA_DIR/stealth.log"

mkdir -p "$DATA_DIR" "$CACHE_DIR" 2>/dev/null

log() { echo "$(date '+%H:%M:%S') [svc] $1" >> "$LOG" 2>/dev/null || true; }

# Wait for boot
until [ "$(getprop sys.boot_completed)" = "1" ] 2>/dev/null; do
    sleep 2
done
log "Boot completed"

sleep 2

# ── Configure Zygisk denylist ───────────────────────────────
# The module must be in the denylist for apps we want to hide from
log "--- Configuring Zygisk denylist ---"

if command -v magisk >/dev/null 2>&1; then
    # Clear existing denylist
    magisk --denylist clear 2>/dev/null || true

    # Add all user apps to denylist so the module loads into them
    # Skip: root manager, system apps, Google apps that need to see real props
    ROOT_MANAGER="com.topjohnwu.magisk"
    
    pm list packages 2>/dev/null | sed 's/package://' | while read -r pkg; do
        [ -z "$pkg" ] && continue
        
        # Skip root manager
        case "$pkg" in
            "$ROOT_MANAGER") continue ;;
            com.topjohnwu.magisk|eu.chainfire.supersu|com.noshufou.android.su|com.koushikdutta.superuser|com.zachspong.temproot|com.topjohnwu.magiskmanager|com.topjohnwu.magiskdeveloper) continue ;;
        esac
        
        # Skip system/Google apps that should see real device info
        case "$pkg" in
            com.android.*|android|com.google.android.inputmethod*|com.google.android.permissioncontroller*) continue ;;
            com.samsung.android.*|com.sec.android.*) continue ;;
            com.xiaomi.*|com.miui.*|com.mi.*|com.redmi.*|com.poco.*) continue ;;
            com.oneplus.*|com.oppo.*|com.vivo.*|com.realme.*|com.iqoo.*|com.honor.*|com.huawei.*|com.hisilicon.*|com.meizu.*|com.nothing.*) continue ;;
        esac
        
        magisk --denylist add "$pkg" 2>/dev/null || true
    done
    
    log "Denylist configured"
else
    log "WARNING: magisk binary not found — skipping denylist"
fi

# ── Refresh root UIDs (apps may have been granted/denied root since last boot) ──
log "--- Refreshing root UIDs ---"

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
    log "Root UIDs refreshed: $(echo $ROOT_UIDS | tr '\n' ' ')"
else
    log "No root UIDs found"
fi

# ── Ensure config is accessible ─────────────────────────────
if [ ! -f "$DATA_DIR/stealth.conf" ]; then
    cp "$MODDIR/common/stealth.conf.default" "$DATA_DIR/stealth.conf" 2>/dev/null
fi
cp "$DATA_DIR/stealth.conf" "$CACHE_DIR/stealth.conf" 2>/dev/null
chmod 644 "$DATA_DIR/stealth.conf" "$CACHE_DIR/stealth.conf" 2>/dev/null

log "=== service.sh v1.3 END ==="
