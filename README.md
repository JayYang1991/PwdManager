# 🔐 PwdManager 密码管理器

PwdManager 是一套安全、轻量、高可用的全栈密码管理系统，包含 **Python 现代化后端服务**、**简美响应式 Web 控制台** 以及 **卡通风格 Android 客户端 APP**。

本系统采用**服务端全权加解密**架构，核心密码数据均通过工业级 **AES-256-GCM + PBKDF2-HMAC-SHA256** 加密存储，支持多端双向同步、一键私钥轮换重加密、私钥与数据一键导入导出，并提供一键编译与自动化安装脚本。

---

## 🌟 核心特性

- 🛡️ **服务端全权加解密**：所有密码的加解密计算均在服务端闭环完成，数据库中仅持久化存储经过 `AES-256-GCM` 认证加密的密文、随机 `IV` 与独立 `Salt`，数据库文件即便泄露也无法逆向破解。
- 🎨 **简美现代化 Web 控制台**：单页响应式管理控制台（SPA），支持卡片流展示、实时模糊搜索、一键显隐与剪贴板复制、在线强密码生成器、数据统计等。
- 📱 **卡通风格 Android 客户端**：精心设计的萌趣卡通保险箱/小锁头矢量图标，支持自定义配置服务器域名、用户名与密码鉴权登录，APP 启动时自动从服务端双向增量同步，本地新增/修改/删除实时推送到服务端。
- 🔄 **一键更换加密私钥 (Key Rotation)**：支持在线轮换主加密私钥；更换时服务端自动使用旧私钥解密所有现有记录，并立即使用新私钥重新加密写入数据库。
- 📥 **私钥与记录一键导入/导出**：支持一键导出包含当前主私钥、所有密码记录及 SHA-256 完整性校验和的 JSON 备份；支持一键导入并支持**指定新的加密私钥**。
- 🌐 **服务端网站直下 APP**：服务端直接托管安卓安装包（`/download/app.apk`），并在 Web 控制台首屏与导航栏提供直接下载入口。
- 🔨 **一键编译与发布系统**：提供 `build_all.sh` 脚本，自动化完成 Android APK 编译、服务端发布包打包及一键安装脚本生成。

---

## 📂 项目目录结构

```
PwdManager/
├── android/                      # Android 原生客户端源码 (Java + AndroidX)
│   ├── app/                      # APP 模块源码
│   │   ├── src/main/AndroidManifest.xml
│   │   ├── src/main/java/com/pwdmanager/app/
│   │   │   ├── model/            # 数据模型 (PasswordItem)
│   │   │   ├── db/               # 本地 SQLite 缓存 (PasswordDatabaseHelper)
│   │   │   ├── network/          # 网络通信与鉴权 (ApiClient, SyncManager)
│   │   │   ├── crypto/           # 辅助工具 (CryptoUtils)
│   │   │   └── ui/               # 界面交互 (MainActivity, PasswordAdapter)
│   │   └── src/main/res/         # UI 布局、样式及卡通风格矢量图标
│   ├── build.gradle              # Gradle 构建配置
│   └── settings.gradle
├── server/                       # 服务端源码与测试套件
│   ├── app.py                    # REST API 服务端与嵌入式 Web 管理控制台
│   ├── install.sh                # 服务端快速部署安装脚本
│   ├── test_server.py            # 服务端与 API 自动化综合测试套件
│   └── download/                 # 客户端 APK 分发目录
├── dist/                         # 自动化打包输出目录 (由 build_all.sh 生成)
│   ├── PwdManager.apk            # 编译完成的安卓客户端安装包
│   ├── pwdmanager-server.tar.gz  # 服务端独立安装包
│   └── install_server.sh         # 服务端一键独立安装脚本
├── build_all.sh                  # 🔨 一键编译打包全套组件脚本
├── test_app_integration.sh       # 📱 自动化启动安卓模拟器并进行端到端联调测试脚本
└── README.md                     # 项目使用与架构说明文档
```

---

## 🚀 快速开始与部署

### 1. 服务端访问与默认凭据

若已部署在局域网服务器（如 `192.168.122.100`）：
- **Web 管理控制台**：`http://192.168.122.100:8000`
- **安卓客户端直接下载**：`http://192.168.122.100:8000/download/app.apk`
- **默认登录账号**：`jason`
- **默认登录密码**：`JYang@1991`

---

### 2. 一键编译打包 (本地构建)

在项目根目录下执行一键打包脚本：
```bash
./build_all.sh
```
该脚本将自动：
1. 调用 Gradle 编译生成最新的 Android Debug APK；
2. 打包生成服务端独立发布包 `dist/pwdmanager-server.tar.gz`（内含 APK 下载支持）；
3. 生成服务器一键部署脚本 `dist/install_server.sh`。

---

### 3. 服务端全新独立部署

在任意 Ubuntu / Debian / CentOS Linux 服务器上，将 `dist/` 中的文件拷贝至服务器并执行：
```bash
sudo bash install_server.sh
```
脚本将自动配置 Python3 环境、安装 systemd 服务 `pwdmanager.service`、设置开机自启并启动在端口 `8000`。

---

### 4. 安卓模拟器联调与验证

本地已配置 Android SDK 与 AVD 虚拟设备（`Pixel_6_API_34`），可直接执行端到端自动化测试：
```bash
./test_app_integration.sh
```
或者手动启动模拟器：
```bash
start-android-emulator
```

在安卓 APP 内点击右上角 ⚙️ **设置** 图标，即可随时修改：
- **服务器域名/IP 地址**（如 `http://192.168.122.100:8000`）
- **用户名**（如 `jason`）
- **密码**（如 `JYang@1991`）

---

## 📡 API 接口参考

| 路由 / 路径 | 方法 | 权限 | 说明 |
| :--- | :--- | :--- | :--- |
| `/` 或 `/admin` | `GET` | 公开 | 访问简美 Web 管理控制台 |
| `/download/app.apk` | `GET` | 公开 | 下载安卓客户端 APK 安装包 |
| `/api/health` | `GET` | 公开 | 服务端健康状态检查 |
| `/api/auth/login` | `POST` | 公开 | 用户与管理员登录鉴权，获取 Token |
| `/api/passwords` | `GET` | 需鉴权 | 获取密码记录列表（支持 `?decrypt=1` 解密） |
| `/api/passwords` | `POST` | 需鉴权 | 创建新密码记录（服务端自动完成 AES 加密） |
| `/api/passwords/{id}` | `PUT` | 需鉴权 | 更新密码记录 |
| `/api/passwords/{id}` | `DELETE`| 需鉴权 | 软删除密码记录 |
| `/api/passwords/sync` | `POST` | 需鉴权 | 客户端与服务端双向增量同步 |
| `/api/admin/key` | `GET/POST`| Admin | 查看或更新服务端当前主私钥 |
| `/api/admin/rotate-key` | `POST` | Admin | **一键更换私钥**（自动解密并使用新私钥重加密） |
| `/api/admin/export` | `GET` | Admin | **一键导出**私钥与全部密码记录（含完整性校验和） |
| `/api/admin/import` | `POST` | Admin | **一键导入**密码记录并支持**指定加密私钥** |

---

## 🔒 安全加密设计原理

1. **密钥派生 (KDF)**：
   采用 `PBKDF2WithHmacSHA256` 算法，配置 65,536 次哈希迭代与 16 字节随机盐值，将主密钥派生为 256 位高强度对称密钥。
2. **认证加密 (AEAD)**：
   采用 `AES-256-GCM (Galois/Counter Mode)`，每次加密生成唯一的 12 字节初始化向量（IV），并附加 128 位认证标签（Auth Tag），有效防御密文篡改与重放攻击。
3. **传输与存储安全**：
   所有端点均基于 HTTP Token 鉴权（`Authorization: Bearer <token>`），数据库采用 WAL 模式保证高并发读写安全。
