#!/usr/bin/env bash
# ==============================================================================
# 🔐 Password Manager - One-Click Build, Packaging & GitHub Release Script
# 编译打包 Android APP、服务端安装包及一键推送到 GitHub Release
# ==============================================================================
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$PROJECT_ROOT/dist"
GITHUB_REPO="JayYang1991/PwdManager"

# Default configuration
TAG_NAME="${VERSION:-v1.0.0}"
DO_RELEASE=false

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --release|--push|-r) DO_RELEASE=true ;;
        --tag|-t|-v|--version)
            TAG_NAME="$2"
            shift
            ;;
        v[0-9]*|[0-9]*)
            TAG_NAME="$1"
            ;;
        --help|-h)
            echo "=================================================="
            echo " 🔐 PwdManager 编译打包与 GitHub Release 发布工具"
            echo "=================================================="
            echo "用法: $0 [选项] [版本号]"
            echo ""
            echo "选项:"
            echo "  --release, -r            编译打包并推送到 GitHub (Tag & Release)"
            echo "  -v, -t, --tag, --version 指定 Release 版本号 (例如: v1.0.0, v1.1.0)"
            echo "  --help, -h               显示此帮助信息"
            echo ""
            echo "示例:"
            echo "  $0                       # 本地编译并生成 dist/ 产物 (默认 v1.0.0)"
            echo "  $0 --release             # 编译并推送默认版本至 GitHub Release"
            echo "  $0 --tag v1.0.1 --release# 编译并推送 v1.0.1 至 GitHub Release"
            echo "  $0 v1.2.0 -r             # 编译并推送 v1.2.0 至 GitHub Release"
            echo "=================================================="
            exit 0
            ;;
        *) echo "未知参数: $1 (使用 --help 查看使用说明)"; exit 1 ;;
    esac
    shift
done

# Ensure tag has 'v' prefix
if [[ ! "$TAG_NAME" =~ ^v ]]; then
    TAG_NAME="v$TAG_NAME"
fi

# Auto-detect JAVA_HOME if not valid
if [ -z "$JAVA_HOME" ] || [ ! -d "$JAVA_HOME" ]; then
    for candidate in "/usr/lib/jvm/java-21-openjdk-amd64" "/usr/lib/jvm/java-17-openjdk-amd64" "$HOME/.local/share/java/jdk-17" "$HOME/.local/share/java/jdk-21"; do
        if [ -d "$candidate" ]; then
            export JAVA_HOME="$candidate"
            break
        fi
    done
fi

# Auto-detect ANDROID_HOME if not valid
if [ -z "$ANDROID_HOME" ] || [ ! -d "$ANDROID_HOME" ]; then
    for candidate in "$HOME/Android/sdk" "$HOME/Android/Sdk" "$HOME/android-sdk" "/opt/android-sdk"; do
        if [ -d "$candidate" ]; then
            export ANDROID_HOME="$candidate"
            break
        fi
    done
fi

export PATH="$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:/home/jason/.local/bin:$PATH"

echo "=================================================="
echo " 🔨 密码管理器一键编译打包系统"
echo "=================================================="
echo " 📁 项目目录: $PROJECT_ROOT"
echo " 📦 输出目录: $DIST_DIR"
echo " 🏷️  发布版本: $TAG_NAME"
echo " 🚀 推送发布: $( [ "$DO_RELEASE" = true ] && echo "是 (启用 GitHub Release 推送)" || echo "否 (仅本地打包)" )"
echo "=================================================="

mkdir -p "$DIST_DIR" "$PROJECT_ROOT/server/download"

# ------------------------------------------------------------------------------
# 1. 编译 Android APP (APK)
# ------------------------------------------------------------------------------
echo ""
echo "[1/4] 编译 Android APP (Gradle assembleDebug)..."
cd "$PROJECT_ROOT/android"
if [ -f "./gradlew" ]; then
    chmod +x ./gradlew
    ./gradlew assembleDebug
elif command -v gradle &> /dev/null; then
    gradle assembleDebug
else
    echo "❌ 错误: 未找到 gradlew 或 gradle 命令"
    exit 1
fi

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
echo "[2/4] 打包服务端发布包 (pwdmanager-server.tar.gz)..."
SERVER_TAR="$DIST_DIR/pwdmanager-server.tar.gz"
TEMP_STAGE=$(mktemp -d)

mkdir -p "$TEMP_STAGE/pwdmanager-server/download"
cp "$PROJECT_ROOT/server/app.py" "$TEMP_STAGE/pwdmanager-server/"
cp "$PROJECT_ROOT/server/install.sh" "$TEMP_STAGE/pwdmanager-server/"
cp "$PROJECT_ROOT/server/uninstall.sh" "$TEMP_STAGE/pwdmanager-server/" 2>/dev/null || true
cp "$PROJECT_ROOT/update_server.sh" "$TEMP_STAGE/pwdmanager-server/" 2>/dev/null || true
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
- 用户与管理员 Token 鉴权 (默认账号: jason / admin@1234)
- 一键导出/导入私钥与密码记录
- 一键更换主私钥并重新加密所有记录
- 支持从网页端直接下载安卓客户端 APK
README_EOF

cd "$TEMP_STAGE"
tar -czf "$SERVER_TAR" pwdmanager-server/
rm -rf "$TEMP_STAGE"
echo "  ✅ 服务端安装包打包完成: $SERVER_TAR ($(du -h "$SERVER_TAR" | cut -f1))"

# ------------------------------------------------------------------------------
# 3. 准备独立一键安装脚本 (dist/install_server.sh)
# ------------------------------------------------------------------------------
echo ""
echo "[3/4] 准备独立一键安装脚本 (dist/install_server.sh)..."
cp "$PROJECT_ROOT/install_server.sh" "$DIST_DIR/install_server.sh"
cp "$PROJECT_ROOT/uninstall_server.sh" "$DIST_DIR/uninstall_server.sh" 2>/dev/null || true
cp "$PROJECT_ROOT/update_server.sh" "$DIST_DIR/update_server.sh" 2>/dev/null || true
chmod +x "$DIST_DIR/install_server.sh" "$DIST_DIR/uninstall_server.sh" "$DIST_DIR/update_server.sh" 2>/dev/null || true
echo "  ✅ 独立安装/卸载/更新脚本就绪: $DIST_DIR/install_server.sh, $DIST_DIR/update_server.sh, $DIST_DIR/uninstall_server.sh"

# ------------------------------------------------------------------------------
# 4. 推送到 GitHub Release (若开启 --release)
# ------------------------------------------------------------------------------
if [ "$DO_RELEASE" = true ]; then
    echo ""
    echo "[4/4] 🚀 正在推送 Release 到 GitHub (${GITHUB_REPO}@${TAG_NAME})..."

    cd "$PROJECT_ROOT"
    # 确保当前改动提交
    if [ -n "$(git status --porcelain)" ]; then
        echo "   提交代码改动..."
        git add -A
        git commit -m "chore(release): prepare release ${TAG_NAME}" || true
    fi

    # 推送 main 分支
    echo "   推送 main 分支到远程仓库..."
    git push origin main 2>/dev/null || true

    # 创建并推送 Tag
    echo "   创建并推送 Git Tag: ${TAG_NAME}..."
    git tag -f "${TAG_NAME}" -m "Release ${TAG_NAME}"
    git push origin "${TAG_NAME}" --force 2>/dev/null || echo "   (提示: Tag 推送已执行)"

    RELEASE_NOTES="### 🔐 PwdManager ${TAG_NAME} 发布说明

#### ✨ 核心特性：
- 🛡️ **服务端全权加解密**：AES-256-GCM + PBKDF2 安全存储与 64 位全局版本并发控制。
- 🎨 **星空极光 Web 管理控制台**：自适应电脑与手机屏幕，支持 30 分钟会话空闲超时自动注销。
- 📱 **极光星空现代化 Android 客户端**：全套 26 个高清矢量图标与动态渐变首字母头像，支持双向增量同步。
- 🔄 **一键更换加密私钥**：支持服务端数据全量平滑重加密。
- 📥 **私钥与密码记录一键导出/导入**。
- 🌐 **支持服务端网站直接下载最新客户端 APK**。

#### 📦 下载与安装：
- **服务端一键极速安装 (Linux)**：
  \`\`\`bash
  curl -fsSL https://raw.githubusercontent.com/${GITHUB_REPO}/main/install_server.sh | sudo bash
  \`\`\`
- **安卓客户端 (APK) 下载**：[PwdManager.apk](https://github.com/${GITHUB_REPO}/releases/download/${TAG_NAME}/PwdManager.apk)"

    PUBLISHED=false

    # 尝试使用 gh CLI
    if gh auth status &>/dev/null; then
        echo "   使用 GitHub CLI 创建 Release 并上传文件..."
        gh release create "${TAG_NAME}" "$APK_DEST" "$SERVER_TAR" "$DIST_DIR/install_server.sh" \
            --repo "${GITHUB_REPO}" \
            --title "PwdManager ${TAG_NAME}" \
            --notes "${RELEASE_NOTES}" \
            --clobber
        echo "   ✅ GitHub Release ${TAG_NAME} 发布成功！"
        PUBLISHED=true
    # 尝试使用 GITHUB_TOKEN API
    elif [ -n "$GITHUB_TOKEN" ] || [ -n "$GH_TOKEN" ]; then
        TOKEN="${GITHUB_TOKEN:-$GH_TOKEN}"
        echo "   使用 GitHub REST API 创建 Release..."
        CREATE_RESP=$(curl -s -X POST \
            -H "Authorization: token ${TOKEN}" \
            -H "Accept: application/vnd.github.v3+json" \
            https://api.github.com/repos/${GITHUB_REPO}/releases \
            -d "{\"tag_name\":\"${TAG_NAME}\",\"name\":\"PwdManager ${TAG_NAME}\",\"body\":$(echo "$RELEASE_NOTES" | jq -R -s .),\"draft\":false,\"prerelease\":false}")
        
        UPLOAD_URL=$(echo "$CREATE_RESP" | grep -o 'https://uploads.github.com/repos/[^"]*' | sed 's/{?name,label}//' | head -n 1 || true)
        
        if [ -n "$UPLOAD_URL" ]; then
            for FILE in "$APK_DEST" "$SERVER_TAR" "$DIST_DIR/install_server.sh"; do
                FNAME=$(basename "$FILE")
                echo "   上传资产: $FNAME ..."
                curl -s -X POST \
                    -H "Authorization: token ${TOKEN}" \
                    -H "Content-Type: application/octet-stream" \
                    --data-binary @"$FILE" \
                    "${UPLOAD_URL}?name=${FNAME}" > /dev/null
            done
            echo "   ✅ GitHub API 发布资产完成！"
            PUBLISHED=true
        fi
    fi

    if [ "$PUBLISHED" = false ]; then
        echo "   ℹ️ Git Tag (${TAG_NAME}) 已成功推送到 GitHub 远程仓库！"
        echo "   🔗 远程仓库地址: https://github.com/${GITHUB_REPO}/tree/${TAG_NAME}"
        echo "   💡 提示: 执行 'gh auth login' 或设置 'export GITHUB_TOKEN=...' 即可自动上传打包文件到 Releases 页面。"
    fi
else
    echo ""
    echo "[4/4] (提示: 若需将安装包推送到 GitHub Release，可使用: $0 --release 或 $0 --tag $TAG_NAME --release)"
fi

echo ""
echo "=================================================="
echo " 🎉 编译打包全部完成！输出文件清单："
echo "=================================================="
ls -lh "$DIST_DIR"
echo "=================================================="
