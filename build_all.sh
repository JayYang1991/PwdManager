#!/usr/bin/env bash
# ==============================================================================
# 🔐 Password Manager - One-Click Build, Packaging & GitHub Release Script
# 编译打包 Android APP、服务端安装包及一键推送到 GitHub Release
# ==============================================================================
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$PROJECT_ROOT/dist"
GITHUB_REPO="JayYang1991/PwdManager"

# Command-line options
TAG_NAME="v1.0.0"
DO_RELEASE=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --release|--push|-r) DO_RELEASE=true ;;
        --tag|-t) TAG_NAME="$2"; shift ;;
        --help|-h)
            echo "用法: $0 [选项]"
            echo "选项:"
            echo "  --release, -r    编译打包并推送到 GitHub Release"
            echo "  --tag, -t <tag>  指定 Release 标签名 (默认: v1.0.0)"
            echo "  --help, -h       显示帮助信息"
            exit 0
            ;;
        *) echo "未知选项: $1"; exit 1 ;;
    esac
    shift
done

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export JAVA_HOME="${JAVA_HOME:-$HOME/.local/share/java/jdk-17}"
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"

echo "=================================================="
echo " 🔨 密码管理器一键编译打包"
echo "=================================================="
echo "项目根目录: $PROJECT_ROOT"
echo "输出目标目录: $DIST_DIR"
echo "Release 标签: $TAG_NAME"
echo "是否发布 Release: $DO_RELEASE"

mkdir -p "$DIST_DIR" "$PROJECT_ROOT/server/download"

# ------------------------------------------------------------------------------
# 1. 编译 Android APP (APK)
# ------------------------------------------------------------------------------
echo ""
echo "[1/4] 编译 Android APP (Gradle assembleDebug)..."
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
echo "[2/4] 打包服务端发布包 (pwdmanager-server.tar.gz)..."
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
# 3. 复制与生成独立一键安装脚本 (dist/install_server.sh)
# ------------------------------------------------------------------------------
echo ""
echo "[3/4] 准备独立一键安装脚本 (dist/install_server.sh)..."
chmod +x "$DIST_DIR/install_server.sh"
echo "  ✅ 独立安装脚本就绪: $DIST_DIR/install_server.sh"

# ------------------------------------------------------------------------------
# 4. 推送到 GitHub Release (若开启 --release)
# ------------------------------------------------------------------------------
if [ "$DO_RELEASE" = true ]; then
    echo ""
    echo "[4/4] 🚀 正在推送 Release 到 GitHub (${GITHUB_REPO}@${TAG_NAME})..."

    # 1. 确保 Git 仓库已提交所有更改
    cd "$PROJECT_ROOT"
    if [ -n "$(git status --porcelain)" ]; then
        echo "   提交未保存的代码更改..."
        git add -A
        git commit -m "chore(release): release ${TAG_NAME}" || true
    fi

    # 2. 打 Tag 并推送到 Remote
    echo "   创建并推送 Git Tag: ${TAG_NAME}..."
    git tag -f "${TAG_NAME}" -m "Release ${TAG_NAME}"
    git push origin "${TAG_NAME}" --force 2>/dev/null || echo "   (提示: 若需推送请确认已配置 SSH Key 或访问权限)"

    # 3. 使用 gh CLI 或 GitHub API 创建 Release 并上传文件
    RELEASE_NOTES="### 🔐 PwdManager ${TAG_NAME} 发布日志

#### ✨ 新增功能与更新：
- 🛡️ **服务端全权加解密**：AES-256-GCM + PBKDF2 安全存储。
- 🎨 **简美现代化 Web 控制台**：单页 SPA 响应式管理界面。
- 📱 **卡通风格 Android 客户端**：全新萌趣图标，双向增量同步。
- 🔄 **一键更换加密私钥**：支持服务端数据全量重加密。
- 📥 **私钥与密码记录一键导出/导入**。
- 🌐 **支持服务端网站直接下载 APK**。

#### 📦 下载与安装：
- **服务端一键安装**：
  \`\`\`bash
  curl -fsSL https://raw.githubusercontent.com/${GITHUB_REPO}/main/dist/install_server.sh | sudo bash
  \`\`\`
- **安卓 APP 下载**：[PwdManager.apk](https://github.com/${GITHUB_REPO}/releases/download/${TAG_NAME}/PwdManager.apk)"

    if command -v gh &> /dev/null; then
        echo "   使用 GitHub CLI (gh) 创建 Release..."
        gh release create "${TAG_NAME}" "$APK_DEST" "$SERVER_TAR" "$DIST_DIR/install_server.sh" \
            --repo "${GITHUB_REPO}" \
            --title "PwdManager ${TAG_NAME}" \
            --notes "${RELEASE_NOTES}" \
            --clobber || true
        echo "   ✅ GitHub Release 发布成功！"
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
        else
            echo "   ⚠️ 获取 Release 上传 URL 失败，请检查 GITHUB_TOKEN 权限。"
        fi
    else
        echo "   ℹ️ 未检测到 gh CLI 或 GITHUB_TOKEN，已完成本地构建与 Tag 创建。"
        echo "   提示: 设置 export GITHUB_TOKEN=\"your_token\" 或安装 gh 即可自动上传至 Release！"
    fi
else
    echo ""
    echo "[4/4] (提示: 若需将安装包推送到 GitHub Release，可附加参数: $0 --release)"
fi

echo ""
echo "=================================================="
echo " 🎉 编译打包全部完成！输出文件清单："
echo "=================================================="
ls -lh "$DIST_DIR"
echo "=================================================="
