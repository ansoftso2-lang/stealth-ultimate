#!/system/bin/sh
# action.sh v1.1 — Status output (no GUI)
MODDIR=${0%/*}
DATA_DIR="/data/adb/stealth_ultimate"

echo "=== Stealth Ultimate v1.1 ==="
echo ""

if [ -f "$DATA_DIR/disable" ]; then
    echo "Status: DISABLED (bootloop protection)"
    exit 0
fi

echo "Status: ACTIVE"

if [ -f "$DATA_DIR/root_uids.txt" ]; then
    UIDS=$(cat "$DATA_DIR/root_uids.txt" 2>/dev/null)
    if [ -n "$UIDS" ]; then
        echo "Root-granted UIDs (exempt from hiding):"
        echo "$UIDS" | while read -r uid; do
            [ -n "$uid" ] && echo "  UID $uid"
        done
    else
        echo "Root-granted UIDs: none (all non-system apps hidden)"
    fi
else
    echo "Root UIDs file: not found (will be created on next boot)"
fi

echo ""
if [ -f "$DATA_DIR/stealth.conf" ]; then
    echo "Config: $DATA_DIR/stealth.conf"
    FP=$(grep "SPOOF_FINGERPRINT=" "$DATA_DIR/stealth.conf" 2>/dev/null | cut -d= -f2)
    [ -n "$FP" ] && echo "Fingerprint: $FP"
    MODEL=$(grep "SPOOF_MODEL=" "$DATA_DIR/stealth.conf" 2>/dev/null | cut -d= -f2)
    [ -n "$MODEL" ] && echo "Model: $MODEL"
else
    echo "Config: not found (using defaults)"
fi

echo ""
echo "All hiding and spoofing features: ENABLED"
echo "No GUI — everything works automatically after reboot."
