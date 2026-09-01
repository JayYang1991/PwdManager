#!/usr/bin/env bash
# ==============================================================================
# 🔐 PwdManager 密码管理器服务端自动化安装脚本 (含全量依赖预装)
# ==============================================================================
set -e

SERVICE_PORT="${PORT:-8000}"

# 0. 权限与安装路径适配 (防御 200/CHDIR 权限问题)
if [ "$EUID" -eq 0 ]; then
    if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
        USER_HOME=$(eval echo "~$SUDO_USER")
        INSTALL_DIR="${INSTALL_DIR:-$USER_HOME/pwdmanager}"
        RUN_USER="$SUDO_USER"
    else
        INSTALL_DIR="${INSTALL_DIR:-/opt/pwdmanager}"
        RUN_USER="root"
    fi
    SUDO=""
else
    INSTALL_DIR="${INSTALL_DIR:-$HOME/pwdmanager}"
    RUN_USER="$USER"
    if command -v sudo &> /dev/null; then
        SUDO="sudo"
    else
        echo "❌ 错误: 安装系统依赖需要 root 权限或 sudo 支持！"
        exit 1
    fi
fi

echo "=================================================="
echo " 🚀 安装密码管理器服务端 (Password Manager Server)"
echo "=================================================="
echo " 📂 安装目标路径: $INSTALL_DIR"
echo " 🔌 监听服务端口: $SERVICE_PORT"
echo " 👤 运行服务用户: $RUN_USER"

# ==============================================================================
# 1. 前置安装所有系统与语言依赖组件 (System & Python Dependencies)
# ==============================================================================
echo ""
echo "=================================================="
echo " [1/3] 正在前置检测并安装所有系统依赖组件..."
echo "=================================================="

# 检测并适配多种 Linux 发行版包管理器
if command -v apt-get &> /dev/null; then
    echo "  📦 检测到 Debian / Ubuntu 系统，正在安装依赖组件..."
    export DEBIAN_FRONTEND=noninteractive
    $SUDO apt-get update -y -qq 2>/dev/null || true
    $SUDO apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-dev \
        python3-cryptography \
        sqlite3 \
        curl \
        tar \
        gzip \
        ca-certificates \
        build-essential \
        libssl-dev \
        libffi-dev 2>/dev/null || true

elif command -v dnf &> /dev/null; then
    echo "  📦 检测到 Fedora / RHEL 8+ 系统，正在安装依赖..."
    $SUDO dnf install -y \
        python3 \
        python3-pip \
        python3-devel \
        python3-cryptography \
        sqlite \
        curl \
        tar \
        gzip \
        ca-certificates \
        gcc \
        libffi-devel \
        openssl-devel 2>/dev/null || true

elif command -v yum &> /dev/null; then
    echo "  📦 检测到 CentOS / RHEL 7 系统，正在安装依赖..."
    $SUDO yum install -y \
        python3 \
        python3-pip \
        python3-devel \
        python3-cryptography \
        sqlite \
        curl \
        tar \
        gzip \
        ca-certificates \
        gcc \
        libffi-devel \
        openssl-devel 2>/dev/null || true

elif command -v pacman &> /dev/null; then
    echo "  📦 检测到 Arch Linux 系统，正在安装依赖..."
    $SUDO pacman -Sy --noconfirm python python-pip python-cryptography sqlite curl tar gzip ca-certificates base-devel 2>/dev/null || true

elif command -v apk &> /dev/null; then
    echo "  📦 检测到 Alpine Linux 系统，正在安装依赖..."
    $SUDO apk update
    $SUDO apk add --no-cache python3 py3-pip py3-cryptography sqlite tar gzip curl ca-certificates gcc python3-dev musl-dev libffi-dev openssl-dev 2>/dev/null || true
fi

# 确保 Python3 安装成功
if ! command -v python3 &> /dev/null; then
    echo "❌ 错误: Python3 安装失败，请检查系统软件源配置！"
    exit 1
fi

# 确保 Python cryptography 模块可用
echo "  🔍 正在验证 Python 加密库 (cryptography & AES-256-GCM)..."
python3 -c "import cryptography; from cryptography.hazmat.primitives.ciphers.aead import AESGCM" 2>/dev/null || {
    echo "  ⚠️ 系统自带 cryptography 缺失，正在使用 pip3 自动补全安装..."
    $SUDO pip3 install --upgrade pip 2>/dev/null || true
    $SUDO pip3 install cryptography --break-system-packages 2>/dev/null || $SUDO pip3 install cryptography || true
}

# 终检核心组件
python3 -c "
import sys, sqlite3, cryptography
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
print('  ✅ 所有核心依赖组件（Python3、SQLite3、AES-256-GCM、PBKDF2）前置校验通过！')
" || {
    echo "❌ 严重错误: 核心依赖组件未能成功加载！"
    exit 1
}

# ==============================================================================
# 2. 部署服务端文件 (Server Files Deployment)
# ==============================================================================
echo ""
echo "=================================================="
echo " [2/3] 正在部署服务端程序与静态文件..."
echo "=================================================="
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/download"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cp "$SCRIPT_DIR/app.py" "$INSTALL_DIR/"
if [ -f "$SCRIPT_DIR/update_server.sh" ]; then
    cp "$SCRIPT_DIR/update_server.sh" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/update_server.sh"
    if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ] || [ "$EUID" -eq 0 ] || [ -n "$SUDO" ]; then
        $SUDO ln -sf "$INSTALL_DIR/update_server.sh" /usr/local/bin/pwdmanager-update 2>/dev/null || true
    fi
fi
if [ -f "$SCRIPT_DIR/download/PwdManager.apk" ]; then
    cp "$SCRIPT_DIR/download/PwdManager.apk" "$INSTALL_DIR/download/"
fi
chmod +x "$INSTALL_DIR/app.py"

if [ -n "$SUDO" ] || [ "$EUID" -eq 0 ]; then
    chown -R "$RUN_USER" "$INSTALL_DIR" 2>/dev/null || true
fi
echo "  ✅ 文件已就绪: $INSTALL_DIR/app.py, $INSTALL_DIR/update_server.sh"

# ==============================================================================
# 3. 配置并启动 Systemd 服务 (Systemd Service Setup)
# ==============================================================================
echo ""
echo "=================================================="
echo " [3/3] 正在配置 systemd 开机自启服务..."
echo "=================================================="
SERVICE_NAME="pwdmanager"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

$SUDO bash -c "cat << SERVICE_CONF > $SERVICE_FILE
[Unit]
Description=Password Manager Backend Server & Web Dashboard
After=network.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/app.py $SERVICE_PORT
Restart=always
RestartSec=3
Environment=PWD_DB_PATH=$INSTALL_DIR/passwords.db
Environment=PWD_DOWNLOAD_DIR=$INSTALL_DIR/download

[Install]
WantedBy=multi-user.target
SERVICE_CONF"

if command -v systemctl &> /dev/null; then
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
    $SUDO systemctl restart "$SERVICE_NAME"
    echo "  ✅ systemd 服务已启动并设置开机自启 ($SERVICE_NAME)"
else
    echo "  ⚠️ 未检测到 systemd，使用后台守护进程运行..."
    pkill -f "python3 $INSTALL_DIR/app.py" 2>/dev/null || true
    nohup /usr/bin/python3 "$INSTALL_DIR/app.py" "$SERVICE_PORT" > "$INSTALL_DIR/server.log" 2>&1 &
fi

# 获取主机 IP
IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

echo ""
echo "=================================================="
echo " 🎉 密码管理器服务端安装成功！"
echo "=================================================="
echo " 🌐 Web 管理控制台:  http://${IP_ADDR}:${SERVICE_PORT}"
echo " 📱 安卓客户端下载:  http://${IP_ADDR}:${SERVICE_PORT}/download/app.apk"
echo " 🔑 默认管理员账号:  admin (或 jason)"
echo " 🔒 默认管理员密码:  admin@1234"
echo " 📁 数据存储目录:    $INSTALL_DIR"
echo "=================================================="
