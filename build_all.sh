#!/usr/bin/env bash
# ==============================================================================
# Password Manager - One-Click Build & Packaging Script
# 编译打包 Android APP、服务端安装包及自动化安装脚本
# ==============================================================================
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$PROJECT_ROOT/dist"

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export JAVA_HOME="${JAVA_HOME:-$HOME/.local/share/java/jdk-17}"
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"

echo "=================================================="
echo " 🔨 密码管理器一键编译打包"
echo "=================================================="
echo "项目路径: $PROJECT_ROOT"
echo "输出目录: $DIST_DIR"

mkdir -p "$DIST_DIR" "$PROJECT_ROOT/server/download"

# ------------------------------------------------------------------------------
# 1. 编译 Android APP (APK)
# ------------------------------------------------------------------------------
echo ""
echo "[1/3] 编译 Android APP (Gradle assembleDebug)..."
cd "$PROJECT_ROOT/android"
gradle assembleDebug

APK_SRC="$PROJECT_ROOT/android/app/build/outputs/apk/debug/app-debug.apk"
if [ ! -f "$APK_SRC" ]; then
    echo "❌ 编译失败: 未找到生成的 APK 文件！"
    exit 1
fi

APK_DEST="$DIST_DIR/PwdManager.apk"
cp "$APK_SRC" "$APK_DEST"
cp "$APK_SRC" "$PROJECT_ROOT/server/download/PwdManager.apk"
echo "  ✅ Android APP 打包完成: $APK_DEST ($(du -h "$APK_DEST" | cut -f1))"

# ------------------------------------------------------------------------------
# 2. 打包服务端安装包 (pwdmanager-server.tar.gz)
# ------------------------------------------------------------------------------
echo ""
echo "[2/3] 打包服务端发布包 (pwdmanager-server.tar.gz)..."
SERVER_TAR="$DIST_DIR/pwdmanager-server.tar.gz"
TEMP_STAGE=$(mktemp -d)

mkdir -p "$TEMP_STAGE/pwdmanager-server/download"
cp "$PROJECT_ROOT/server/app.py" "$TEMP_STAGE/pwdmanager-server/"
cp "$PROJECT_ROOT/server/install.sh" "$TEMP_STAGE/pwdmanager-server/"
cp "$APK_DEST" "$TEMP_STAGE/pwdmanager-server/download/PwdManager.apk"

cat << 'README_EOF' > "$TEMP_STAGE/pwdmanager-server/README.md"
# 密码管理器服务端 (Password Manager Server)

## 快速安装与运行
直接在服务器上执行：
```bash
bash install.sh
```

## 服务端功能
- 服务端全权加解密 (AES-256-GCM + PBKDF2)
- 简美现代化 Web 管理控制台 (http://<ip>:8000)
- 用户与管理员 Token 鉴权 (默认账号: jason / JYang@1991)
- 一键导出/导入私钥与密码记录
- 一键更换主私钥并重新加密所有记录
- 支持从网页端直接下载安卓客户端 APK
README_EOF

cd "$TEMP_STAGE"
tar -czf "$SERVER_TAR" pwdmanager-server/
rm -rf "$TEMP_STAGE"
echo "  ✅ 服务端安装包打包完成: $SERVER_TAR ($(du -h "$SERVER_TAR" | cut -f1))"

# ------------------------------------------------------------------------------
# 3. 生成独立一键部署安装脚本 (install_server.sh)
# ------------------------------------------------------------------------------
echo ""
echo "[3/3] 生成独立一键安装脚本 (dist/install_server.sh)..."
cat << 'INSTALLER_SH_EOF' > "$DIST_DIR/install_server.sh"
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
INSTALLER_SH_EOF
chmod +x "$DIST_DIR/install_server.sh"

echo "  ✅ 独立安装脚本生成完成: $DIST_DIR/install_server.sh"

# ------------------------------------------------------------------------------
# 汇总结果
# ------------------------------------------------------------------------------
echo ""
echo "=================================================="
echo " 🎉 编译打包全部完成！输出文件清单："
echo "=================================================="
ls -lh "$DIST_DIR"
echo "=================================================="
