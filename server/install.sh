#!/usr/bin/env bash
# ==============================================================================
# Password Manager Server - Automated Installer Script
# ==============================================================================
set -e

INSTALL_DIR="${INSTALL_DIR:-$HOME/pwdmanager}"
SERVICE_PORT="${PORT:-8000}"

echo "=================================================="
echo " 🚀 安装密码管理器服务端 (Password Manager Server)"
echo "=================================================="
echo "安装目标路径: $INSTALL_DIR"
echo "监听服务端口: $SERVICE_PORT"

# 1. Check Python3
if ! command -v python3 &> /dev/null; then
    echo "正在安装 Python3..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-cryptography
    elif command -v yum &> /dev/null; then
        sudo yum install -y python3 python3-pip
    fi
fi

# Ensure cryptography is available
python3 -c "import cryptography" 2>/dev/null || {
    echo "正在安装 Python cryptography 库..."
    pip3 install cryptography --break-system-packages 2>/dev/null || pip3 install cryptography || true
}

# 2. Setup directory
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/download"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cp "$SCRIPT_DIR/app.py" "$INSTALL_DIR/"
if [ -f "$SCRIPT_DIR/download/PwdManager.apk" ]; then
    cp "$SCRIPT_DIR/download/PwdManager.apk" "$INSTALL_DIR/download/"
fi
chmod +x "$INSTALL_DIR/app.py"

# 3. Configure systemd service
SERVICE_NAME="pwdmanager"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

echo "正在配置 systemd 系统服务..."
$SUDO bash -c "cat << 'SERVICE_CONF' > $SERVICE_FILE
[Unit]
Description=Password Manager Backend Server & Web Dashboard
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/app.py $SERVICE_PORT
Restart=always
RestartSec=3
Environment=PWD_DB_PATH=$INSTALL_DIR/passwords.db
Environment=PWD_DOWNLOAD_DIR=$INSTALL_DIR/download

[Install]
WantedBy=multi-user.target
SERVICE_CONF"

$SUDO systemctl daemon-reload
$SUDO systemctl enable "$SERVICE_NAME"
$SUDO systemctl restart "$SERVICE_NAME"

# 4. Get Host IP
IP_ADDR=$(hostname -I | awk '{print $1}' || echo "127.0.0.1")

echo ""
echo "=================================================="
echo " ✅ 服务端安装启动成功！"
echo "=================================================="
echo " 🌐 Web 管理控制台:  http://${IP_ADDR}:${SERVICE_PORT}"
echo " 📱 安卓客户端下载:  http://${IP_ADDR}:${SERVICE_PORT}/download/app.apk"
echo " 🔑 默认管理员账号:  jason"
echo " 🔒 默认管理员密码:  JYang@1991"
echo "=================================================="
