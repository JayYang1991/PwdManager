#!/usr/bin/env bash
# ==============================================================================
# 🔄 PwdManager 服务端平滑在线更新脚本 (从 GitHub Release 拉取并无损保留数据)
# ==============================================================================
set -e

GITHUB_REPO="JayYang1991/PwdManager"
RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/pwdmanager-server.tar.gz"
RAW_BASE_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main"

echo "=================================================="
echo " 🔄 密码管理器服务端平滑更新 (PwdManager Updater)"
echo "=================================================="

# 1. 权限检测与适配
if [ "$EUID" -ne 0 ]; then
    if command -v sudo &> /dev/null; then
        echo "ℹ️ 获取 sudo 权限以更新服务..."
        SUDO="sudo"
    else
        echo "❌ 错误: 服务端更新需要 root 权限或 sudo 支持！"
        exit 1
    fi
else
    SUDO=""
fi

# 2. 自动探测服务端安装目录
INSTALL_DIR=""
if [ -n "$PWD_INSTALL_DIR" ] && [ -d "$PWD_INSTALL_DIR" ]; then
    INSTALL_DIR="$PWD_INSTALL_DIR"
elif [ -n "$SUDO_USER" ] && [ -d "/home/$SUDO_USER/pwdmanager" ]; then
    INSTALL_DIR="/home/$SUDO_USER/pwdmanager"
elif [ -d "$HOME/pwdmanager" ]; then
    INSTALL_DIR="$HOME/pwdmanager"
elif [ -d "/opt/pwdmanager" ]; then
    INSTALL_DIR="/opt/pwdmanager"
elif [ -f "./app.py" ] && [ -f "./passwords.db" ]; then
    INSTALL_DIR="$(pwd)"
fi

if [ -z "$INSTALL_DIR" ] || [ ! -d "$INSTALL_DIR" ]; then
    echo "❌ 错误: 未能定位到密码管理器安装目录 (如 /home/user/pwdmanager 或 /opt/pwdmanager)！"
    exit 1
fi

echo " 📂 目标安装目录: $INSTALL_DIR"

# 3. 数据安全保障：在更新前自动建立数据库快照备份
echo ""
echo "=================================================="
echo " [1/4] 正在建立数据库安全快照备份..."
echo "=================================================="
BACKUP_DIR="$INSTALL_DIR/backups"
$SUDO mkdir -p "$BACKUP_DIR"
BACKUP_FILE="$BACKUP_DIR/passwords_backup_$(date +%Y%m%d_%H%M%S).db"

if [ -f "$INSTALL_DIR/passwords.db" ]; then
    if command -v sqlite3 &> /dev/null; then
        $SUDO sqlite3 "$INSTALL_DIR/passwords.db" ".backup '$BACKUP_FILE'" 2>/dev/null || $SUDO cp -a "$INSTALL_DIR/passwords.db" "$BACKUP_FILE"
    else
        $SUDO cp -a "$INSTALL_DIR/passwords.db" "$BACKUP_FILE"
    fi
    echo "  ✅ 数据库已安全备份至: $BACKUP_FILE ($(du -h "$BACKUP_FILE" 2>/dev/null | cut -f1 || echo 'OK'))"
else
    echo "  ℹ️ 暂无历史数据库文件，将创建全新数据库。"
fi

# 4. 从 GitHub Release 拉取最新发布包
echo ""
echo "=================================================="
echo " [2/4] 正在从 GitHub Release 拉取最新服务端发布包..."
echo "=================================================="
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

AUTH_ARGS=()
if [ -n "$GITHUB_TOKEN" ]; then
    AUTH_ARGS=(-H "Authorization: token $GITHUB_TOKEN")
elif [ -n "$GH_TOKEN" ]; then
    AUTH_ARGS=(-H "Authorization: token $GH_TOKEN")
fi

DOWNLOADED=false
echo "   URL: $RELEASE_URL"
if curl -fL "${AUTH_ARGS[@]}" --connect-timeout 10 -o "$TEMP_DIR/pwdmanager-server.tar.gz" "$RELEASE_URL" 2>/dev/null; then
    echo "   ✅ GitHub Release 安装包下载成功！"
    tar -xzf "$TEMP_DIR/pwdmanager-server.tar.gz" -C "$TEMP_DIR"
    DOWNLOADED=true
else
    echo "   ⚠️ 未在 Release 找到发布包，尝试从 GitHub 源码分支直接拉取更新..."
    mkdir -p "$TEMP_DIR/pwdmanager-server/download"
    if curl -fsSL "${AUTH_ARGS[@]}" -o "$TEMP_DIR/pwdmanager-server/app.py" "${RAW_BASE_URL}/server/app.py" 2>/dev/null && \
       curl -fsSL "${AUTH_ARGS[@]}" -o "$TEMP_DIR/pwdmanager-server/update_server.sh" "${RAW_BASE_URL}/update_server.sh" 2>/dev/null; then
        echo "   ✅ 成功从 GitHub 源码分支拉取最新核心程序！"
        DOWNLOADED=true
    fi
fi

if [ "$DOWNLOADED" != true ]; then
    echo ""
    echo "❌ 错误: 无法从 GitHub 下载更新包！"
    echo "💡 提示: 若为私有仓库，请设置 GITHUB_TOKEN=xxx 后重试。"
    exit 1
fi

# 5. 前置依赖组件与环境健康检测
echo ""
echo "  🔍 正在校验 Python3 与核心加密库 (cryptography)..."
if ! python3 -c "import cryptography; from cryptography.hazmat.primitives.ciphers.aead import AESGCM" 2>/dev/null; then
    echo "  ⚠️ 检测到 Python cryptography 模块缺失，正在自动补全依赖..."
    if command -v apt-get &> /dev/null; then
        $SUDO apt-get update -y -qq 2>/dev/null || true
        $SUDO apt-get install -y --no-install-recommends python3-cryptography 2>/dev/null || true
    elif command -v dnf &> /dev/null; then
        $SUDO dnf install -y python3-cryptography 2>/dev/null || true
    elif command -v yum &> /dev/null; then
        $SUDO yum install -y python3-cryptography 2>/dev/null || true
    fi
    if ! python3 -c "import cryptography" 2>/dev/null; then
        if command -v pip3 &> /dev/null; then
            $SUDO pip3 install cryptography --break-system-packages 2>/dev/null || $SUDO pip3 install cryptography 2>/dev/null || true
        fi
    fi
fi

# 6. 平滑覆盖更新程序文件 (严格保留数据库 passwords.db 与历史配置)
echo ""
echo "=================================================="
echo " [3/4] 正在平滑覆盖程序文件 (保留所有数据与私钥)..."
echo "=================================================="
STAGE_DIR="$TEMP_DIR/pwdmanager-server"

# 覆盖 app.py
if [ -f "$STAGE_DIR/app.py" ]; then
    $SUDO cp -f "$STAGE_DIR/app.py" "$INSTALL_DIR/app.py"
    $SUDO chmod +x "$INSTALL_DIR/app.py"
    echo "  ✅ 服务端核心程序更新成功: $INSTALL_DIR/app.py"
fi

# 覆盖 update_server.sh (优先使用发布包中的脚本，防范 curl | bash 时的空 source 问题)
if [ -f "$STAGE_DIR/update_server.sh" ]; then
    $SUDO cp -f "$STAGE_DIR/update_server.sh" "$INSTALL_DIR/update_server.sh"
elif [ -n "${BASH_SOURCE[0]}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    $SUDO cp -f "${BASH_SOURCE[0]}" "$INSTALL_DIR/update_server.sh" 2>/dev/null || true
fi
$SUDO chmod +x "$INSTALL_DIR/update_server.sh" 2>/dev/null || true

# 覆盖 uninstall.sh (若存在)
if [ -f "$STAGE_DIR/uninstall.sh" ]; then
    $SUDO cp -f "$STAGE_DIR/uninstall.sh" "$INSTALL_DIR/uninstall.sh"
    $SUDO chmod +x "$INSTALL_DIR/uninstall.sh" 2>/dev/null || true
fi

# 覆盖与同步 APK 安装包 (若 release 包未包含则在线补充拉取最新 APK)
$SUDO mkdir -p "$INSTALL_DIR/download"
if [ -f "$STAGE_DIR/download/PwdManager.apk" ]; then
    $SUDO cp -f "$STAGE_DIR/download/PwdManager.apk" "$INSTALL_DIR/download/PwdManager.apk"
    echo "  ✅ 安卓客户端 APK 同步更新成功"
else
    echo "  📥 正在同步最新安卓客户端 (PwdManager.apk)..."
    curl -fL "${AUTH_ARGS[@]}" --connect-timeout 10 -o "$INSTALL_DIR/download/PwdManager.apk" "https://github.com/${GITHUB_REPO}/releases/latest/download/PwdManager.apk" 2>/dev/null || true
    if [ -f "$INSTALL_DIR/download/PwdManager.apk" ]; then
        echo "  ✅ 安卓客户端 APK 在线拉取并更新成功"
    fi
fi

# 建立便捷 CLI 命令
if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ] || [ "$EUID" -eq 0 ] || [ -n "$SUDO" ]; then
    $SUDO ln -sf "$INSTALL_DIR/update_server.sh" /usr/local/bin/pwdmanager-update 2>/dev/null || true
fi

# 7. 平滑重启系统服务并校验运行状态
echo ""
echo "=================================================="
echo " [4/4] 正在平滑重启服务并进行健康状态校验..."
echo "=================================================="

SERVICE_NAME="pwdmanager"
if command -v systemctl &> /dev/null && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    $SUDO systemctl restart "$SERVICE_NAME"
    echo "  ✅ systemd 服务已重启 ($SERVICE_NAME)"
else
    # 非 systemd 守护进程平滑重启
    pkill -f "python3.*app.py" 2>/dev/null || true
    sleep 1
    nohup /usr/bin/python3 "$INSTALL_DIR/app.py" 8000 > "$INSTALL_DIR/server.log" 2>&1 &
    echo "  ✅ 后台进程已重新拉起"
fi

# 健康状态验证
sleep 1.5
HEALTH_OK=false
for i in {1..8}; do
    if curl -s -f http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
        HEALTH_OK=true
        break
    fi
    sleep 1
done

echo ""
echo "=================================================="
if [ "$HEALTH_OK" = true ]; then
    echo " 🎉 密码管理器服务端平滑更新完成！"
    echo "=================================================="
    echo " 🌐 Web 控制台已生效:  http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1'):8000"
    echo " 🛡️ 数据库快照备份位于: $BACKUP_FILE"
    echo " 💡 后续在服务器执行:   sudo pwdmanager-update 即可随时一键更新"
else
    echo " ⚠️ 服务端已更新，但健康探测超时，请使用以下命令查看日志:"
    echo "    journalctl -u pwdmanager -n 50 --no-pager"
fi
echo "=================================================="
