#!/usr/bin/env bash
# ==============================================================================
# 🔐 PwdManager 服务端一键自动化安装脚本 (含全量依赖预装与自动包拉取)
# ==============================================================================
set -e

GITHUB_REPO="JayYang1991/PwdManager"
RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/pwdmanager-server.tar.gz"
RAW_BASE_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main"

echo "=================================================="
echo " 🚀 密码管理器服务端一键安装 (PwdManager Installer)"
echo "=================================================="

# 1. 检查并获取 root / sudo 权限
if [ "$EUID" -ne 0 ]; then
    if command -v sudo &> /dev/null; then
        echo "ℹ️ 获取 sudo 权限以安装系统依赖组件..."
        SUDO="sudo"
    else
        echo "❌ 错误: 执行安装与安装系统依赖需要 root 权限或 sudo 支持！"
        exit 1
    fi
else
    SUDO=""
fi

# 2. 前置安装基础下载与解压工具 (curl, tar, gzip, python3)
echo "📦 正在前置检测基础工具组件 (curl, tar, gzip, python3)..."
if command -v apt-get &> /dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    $SUDO apt-get update -y -qq 2>/dev/null || true
    $SUDO apt-get install -y --no-install-recommends curl tar gzip ca-certificates python3 python3-pip python3-cryptography 2>/dev/null || true
elif command -v dnf &> /dev/null; then
    $SUDO dnf install -y curl tar gzip ca-certificates python3 python3-pip python3-cryptography 2>/dev/null || true
elif command -v yum &> /dev/null; then
    $SUDO yum install -y curl tar gzip ca-certificates python3 python3-pip python3-cryptography 2>/dev/null || true
elif command -v pacman &> /dev/null; then
    $SUDO pacman -Sy --noconfirm curl tar gzip ca-certificates python python-pip python-cryptography 2>/dev/null || true
elif command -v apk &> /dev/null; then
    $SUDO apk add --no-cache curl tar gzip ca-certificates python3 py3-pip py3-cryptography 2>/dev/null || true
fi

# 3. 准备临时安装工作区
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
        echo "   ✅ GitHub Release 安装包下载成功！"
        tar -xzf "$TEMP_DIR/pwdmanager-server.tar.gz" -C "$TEMP_DIR"
    else
        echo "   ⚠️ 未在 Release 找到发布包，尝试从 GitHub 源码分支直接拉取安装..."
        mkdir -p "$TEMP_DIR/pwdmanager-server/download"
        curl -fsSL -o "$TEMP_DIR/pwdmanager-server/app.py" "${RAW_BASE_URL}/server/app.py"
        curl -fsSL -o "$TEMP_DIR/pwdmanager-server/install.sh" "${RAW_BASE_URL}/server/install.sh"
        curl -fsSL -o "$TEMP_DIR/pwdmanager-server/download/PwdManager.apk" "${RAW_BASE_URL}/dist/PwdManager.apk" 2>/dev/null || true
    fi
fi

# 4. 执行全量依赖安装与服务端部署
cd "$TEMP_DIR/pwdmanager-server"
chmod +x install.sh app.py
$SUDO bash install.sh

