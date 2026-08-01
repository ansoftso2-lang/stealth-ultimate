#!/system/bin/sh
# uninstall.sh v1.1
DATA_DIR="/data/adb/stealth_ultimate"
CACHE_DIR="/cache/stealth_ultimate"

rm -rf "$DATA_DIR" 2>/dev/null
rm -rf "$CACHE_DIR" 2>/dev/null
rm -f "/cache/stealth_bootloop" 2>/dev/null
