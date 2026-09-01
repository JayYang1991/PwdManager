#!/usr/bin/env bash
# ==============================================================================
# 🧹 PwdManager 密码管理器服务端一键卸载与环境清理脚本
# ==============================================================================
set -e

SERVICE_NAME="pwdmanager"
SERVICE_PORT="${PORT:-8000}"

echo "=================================================="
echo " 🧹 密码管理器服务端一键卸载 (PwdManager Uninstaller)"
echo "=================================================="

# 1. 检查并获取 root / sudo 权限
if [ "$EUID" -ne 0 ]; then
    if command -v sudo &> /dev/null; then
        echo "ℹ️ 获取 sudo 权限以停止服务并清理系统文件..."
        SUDO="sudo"
    else
        echo "❌ 错误: 卸载服务需要 root 权限或 sudo 支持！"
        exit 1
    fi
else
    SUDO=""
fi

# 2. 停止并注销 systemd 系统服务
echo ""
echo "[1/4] 正在停止并注销 systemd 服务..."
if command -v systemctl &> /dev/null; then
    $SUDO systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    $SUDO systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    $SUDO rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    $SUDO rm -f "/lib/systemd/system/${SERVICE_NAME}.service"
    $SUDO systemctl daemon-reload 2>/dev/null || true
    $SUDO systemctl reset-failed 2>/dev/null || true
    echo "  ✅ systemd 服务已停止并完全移除"
fi

# 终止可能残留的进程
pkill -9 -f "app.py ${SERVICE_PORT}" 2>/dev/null || true
pkill -9 -f "pwdmanager/app.py" 2>/dev/null || true

# 3. 清理所有程序文件、数据库与工作区
echo ""
echo "[2/4] 正在清理服务端程序文件、数据库与下载缓存..."
INSTALL_PATHS=(
    "/home/jason/pwdmanager"
    "/root/pwdmanager"
    "/opt/pwdmanager"
    "$HOME/pwdmanager"
    "/tmp/pwdmanager*"
    "/tmp/tmp.*"
    "/home/jason/pwdmanager-server*"
    "/home/jason/install_server.sh"
    "/home/jason/pwdmanager-server.tar.gz"
)

for path in "${INSTALL_PATHS[@]}"; do
    if [ -e "$path" ] || ls $path >/dev/null 2>&1; then
        $SUDO rm -rf $path
        echo "  🗑️ 已删除: $path"
    fi
done

# 4. 清理系统依赖与无用依赖包 (apt/dnf/yum autoremove)
echo ""
echo "[3/4] 正在清理系统依赖包与缓存..."
if command -v apt-get &> /dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    $SUDO apt-get autoremove -y -qq 2>/dev/null || true
    $SUDO apt-get clean 2>/dev/null || true
    echo "  ✅ apt 依赖包与缓存清理完成"
elif command -v dnf &> /dev/null; then
    $SUDO dnf autoremove -y 2>/dev/null || true
    $SUDO dnf clean all 2>/dev/null || true
    echo "  ✅ dnf 依赖包与缓存清理完成"
elif command -v yum &> /dev/null; then
    $SUDO yum autoremove -y 2>/dev/null || true
    $SUDO yum clean all 2>/dev/null || true
    echo "  ✅ yum 依赖包与缓存清理完成"
fi

# 5. 验证清理结果
echo ""
echo "[4/4] 验证端口与服务状态..."
if ss -tulpn 2>/dev/null | grep -q ":${SERVICE_PORT} "; then
    echo "  ⚠️ 警告: 端口 ${SERVICE_PORT} 仍有进程占用，请手动检查"
else
    echo "  ✅ 端口 ${SERVICE_PORT} 已成功释放"
fi

echo ""
echo "=================================================="
echo " 🎉 密码管理器服务端及全部数据已彻底卸载清理完毕！"
echo "=================================================="
