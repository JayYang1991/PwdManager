#!/usr/bin/env bash
# ==============================================================================
# 🔐 PwdManager 服务端一键自动化安装脚本
# 支持本地安装包或从 GitHub Release / 仓库自动下载安装
# ==============================================================================
set -e

GITHUB_REPO="JayYang1991/PwdManager"
RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/pwdmanager-server.tar.gz"
RAW_BASE_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main"

echo "=================================================="
echo " 🚀 密码管理器服务端一键安装 (PwdManager Installer)"
echo "=================================================="

# 1. 检查并获取 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "⚠️ 检测到当前非 root 用户，尝试获取 sudo 权限..."
    SUDO="sudo"
else
    SUDO=""
fi

# 2. 准备临时工作目录
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
LOCAL_TAR=""

if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/pwdmanager-server.tar.gz" ]; then
    LOCAL_TAR="$SCRIPT_DIR/pwdmanager-server.tar.gz"
elif [ -f "./pwdmanager-server.tar.gz" ]; then
    LOCAL_TAR="./pwdmanager-server.tar.gz"
fi

if [ -n "$LOCAL_TAR" ]; then
    echo "📦 发现本地安装包: $LOCAL_TAR"
    tar -xzf "$LOCAL_TAR" -C "$TEMP_DIR"
else
    echo "🌐 正在从 GitHub Release 下载服务端最新安装包..."
    echo "   URL: $RELEASE_URL"
    if curl -fL --connect-timeout 10 -o "$TEMP_DIR/pwdmanager-server.tar.gz" "$RELEASE_URL" 2>/dev/null; then
        echo "   ✅ GitHub Release 下载成功！"
        tar -xzf "$TEMP_DIR/pwdmanager-server.tar.gz" -C "$TEMP_DIR"
    else
        echo "   ⚠️ 未在 Release 找到发布包，尝试从 GitHub 源码分支自动构建安装..."
        mkdir -p "$TEMP_DIR/pwdmanager-server/download"
        curl -fsSL -o "$TEMP_DIR/pwdmanager-server/app.py" "${RAW_BASE_URL}/server/app.py"
        curl -fsSL -o "$TEMP_DIR/pwdmanager-server/install.sh" "${RAW_BASE_URL}/server/install.sh"
        curl -fsSL -o "$TEMP_DIR/pwdmanager-server/download/PwdManager.apk" "${RAW_BASE_URL}/dist/PwdManager.apk" 2>/dev/null || true
    fi
fi

# 3. 执行安装
cd "$TEMP_DIR/pwdmanager-server"
chmod +x install.sh app.py
$SUDO bash install.sh

