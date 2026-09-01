#!/usr/bin/env bash
# ==============================================================================
# Password Manager Server - One-Line Remote / Local Installer
# ==============================================================================
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAR_FILE="$DIR/pwdmanager-server.tar.gz"

if [ ! -f "$TAR_FILE" ]; then
    echo "❌ 错误: 未找到 $TAR_FILE"
    exit 1
fi

TEMP_EXTRACT=$(mktemp -d)
tar -xzf "$TAR_FILE" -C "$TEMP_EXTRACT"
cd "$TEMP_EXTRACT/pwdmanager-server"
bash install.sh
rm -rf "$TEMP_EXTRACT"
