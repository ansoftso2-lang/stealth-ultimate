#!/bin/bash
# build.sh - Trigger GitHub Actions build and download artifacts
# Usage: ./build.sh

set -e

echo "========================================"
echo "  Stealth Ultimate - GitHub Actions Builder"
echo "========================================"
echo ""

# Check if gh is installed
if ! command -v gh &> /dev/null; then
    echo "[ERROR] GitHub CLI (gh) is not installed."
    echo "Install: https://cli.github.com/"
    exit 1
fi

# Check if user is logged in
if ! gh auth status &> /dev/null; then
    echo "[ERROR] You are not logged in to GitHub CLI."
    echo "Run: gh auth login"
    exit 1
fi

# Get repository info
if [ -z "$1" ]; then
    echo "Enter your GitHub repository (e.g. username/stealth-ultimate):"
    read -r REPO
else
    REPO="$1"
fi

echo ""
echo "Select build action:"
echo "[1] Trigger new build and download"
echo "[2] Only download latest artifact"
echo "[3] Trigger build only"
read -p "> " ACTION

if [ "$ACTION" == "2" ]; then
    echo "[INFO] Downloading latest artifact..."
    gh run download --repo "$REPO" --name stealth-ultimate --dir . --clobber
    echo "[INFO] Done!"
    exit 0
fi

if [ "$ACTION" == "3" ]; then
    echo "[INFO] Triggering build..."
    gh workflow run build.yml --repo "$REPO" --ref main
    echo "[INFO] Workflow triggered! Check GitHub Actions for progress."
    exit 0
fi

echo "[INFO] Triggering GitHub Actions build..."
echo "Repository: $REPO"
echo ""

gh workflow run build.yml --repo "$REPO" --ref main
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to trigger workflow."
    exit 1
fi

echo "[INFO] Workflow triggered! Waiting for completion..."
echo "This may take 5-10 minutes (downloading NDK + compilation)."
echo ""

# Wait for workflow to complete
while true; do
    sleep 30
    STATUS=$(gh run list --repo "$REPO" --workflow=build.yml --limit 1 --json status,conclusion --jq '.[0]' 2>/dev/null || echo "pending")
    echo "Status: $STATUS"
    
    if echo "$STATUS" | grep -q "completed"; then
        if echo "$STATUS" | grep -q "success"; then
            echo "[INFO] Build completed successfully!"
            break
        else
            echo "[ERROR] Build failed! Check GitHub Actions logs."
            exit 1
        fi
    fi
done

echo "[INFO] Downloading artifacts..."
gh run download --repo "$REPO" --name stealth-ultimate --dir . --clobber

if [ -f "stealth_ultimate.zip" ]; then
    echo "[INFO] Module ready: stealth_ultimate.zip"
    echo "Install it via Magisk Manager."
else
    echo "[ERROR] Archive not found after download."
    exit 1
fi
