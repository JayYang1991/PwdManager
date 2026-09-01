# 🔐 PwdManager 密码管理器

PwdManager 是一套安全、轻量、高可用的全栈密码管理系统，包含 **Python 现代化后端服务**、**星空主题响应式 Web 控制台** 以及 **卡通风格 Android 客户端 APP**。

所有密码数据的加解密计算均由服务端安全闭环完成，采用工业级 **AES-256-GCM + PBKDF2-HMAC-SHA256** 加密算法。系统支持 **64 位全局版本号乐观锁（OCC）并发同步**、**双维度防暴力破解与安全审计**、**网站名称唯一性排重**、**一键私钥轮换重加密**、**永久签名与应用内 OTA 更新**。

---

## ⚡ 快速开始 (Quick Start)

### 1. 服务端一键极速安装 (Linux)
在任意 Linux (Ubuntu / Debian / CentOS) 服务器上直接执行以下命令：
```bash
curl -fsSL https://raw.githubusercontent.com/JayYang1991/PwdManager/main/install_server.sh | sudo bash
```
> 脚本将自动检测并安装系统依赖（Python3、SQLite3、Cryptography）、创建 systemd 系统服务、配置开机自启并启动在端口 `8000`。

- **Web 控制台地址**：`http://<服务器IP>:8000`
- **默认管理员账号**：`jason`
- **默认管理员密码**：`admin@1234`

---

### 2. 服务端一键完全卸载与清理 (Linux)
若需卸载服务端并清理所有数据与系统服务，执行：
```bash
curl -fsSL https://raw.githubusercontent.com/JayYang1991/PwdManager/main/uninstall_server.sh | sudo bash
```

---

### 3. 安卓客户端 (APP) 下载与使用
- **方式一（服务端网页直接下载）**：在浏览器打开 `http://<服务器IP>:8000/download/app.apk`
- **方式二（GitHub Release 下载）**：从 [Releases 页面](https://github.com/JayYang1991/PwdManager/releases) 下载最新的 `PwdManager.apk`

打开 APP 后，在右上角 ⚙️ **设置** 中配置服务器地址、用户名及密码即可完成鉴权并开始双向同步：
- **服务器域名/IP**：`http://<服务器IP>:8000`
- **用户名**：`jason`
- **密码**：`admin@1234`

---

### 4. 本地一键编译与打包
```bash
# 本地编译打包 Android APK (带永久签名) 与服务端发布包 (输出至 dist/)
./build_all.sh

# 编译打包并一键推送到 GitHub Release (需配置 GitHub CLI / Token)
./build_all.sh --release
```

---

## 🌟 核心特性与安全设计

### 1. 🛡️ 企业级双维度防暴力破解与时序攻击防御
- **IP + 账号双维度联合频控**：单 IP 或单用户名在 5 分钟内连续失败达 **5 次**，立即触发 **5 分钟**临时安全封禁，下发 HTTP 429 与 `Retry-After` 倒计时；
- **防时序攻击与账号嗅探屏障（Timing Attack Shield）**：提交不存在的用户名时，服务端强制执行同等 **100,000 轮 PBKDF2-HMAC-SHA256** 伪计算，彻底消除响应时间差；
- **渐进式响应延迟**：认证失败引入 0.3s 主动延迟，大幅削弱自动化字典爆破效率；
- **剩余尝试次数反馈**：错误提示精准告知剩余尝试机会（如：`还剩 3 次尝试机会`），成功登录后自动重置计数。

### 2. 📊 登录风控看板与安全审计日志
- **全量安全审计记录**：持久化记录所有登录失败、封禁拦截、成功登录的 `时间`、`来源 IP`、`尝试账号`、`User-Agent` 与 `拦截原因`；
- **Web 可视化风控看板**：Web 控制台顶部提供「**安全审计日志**」专用面板，包含累计失败尝试、异常来源 IP 数、当前封禁目标统计卡片；
- **一键解封与日志管理**：支持查看当前被封禁的 IP/账号倒计时，提供管理员一键解封与日志清空功能。

### 3. 🎯 网站/应用名称唯一性与严格排重
- **以「网站 / 应用名称」为唯一排重键**：不论大小写与首尾空格（`LOWER(TRIM(name))`），系统严格禁止同名重复添加；
- **全栈联动前置拦截**：
  - **新增接口 (`POST`)**：同名记录直接拒绝（HTTP 409: `DUPLICATE_NAME`）；
  - **修改接口 (`PUT`)**：修改为其他已有名称直接拦截；
  - **两路同步 (`Sync`)**：客户端同步同名记录时自动归并更新，避免产生多个副本；
  - **Web & Android 前端**：提交前即时进行同名校验与友好报错。

### 4. ⚡ 64 位全局版本号与乐观并发控制 (OCC)
- **全局原子递增版本号**：服务端通过原子事务维护 64 位 `global_version`，修改/删除操作强制校验版本号；
- **并发写入防覆盖（OCC）**：多个客户端同时修改时，率先到达者成功写入（200 OK），落后者安全拦截（409 Conflict: `VERSION_MISMATCH`）；
- **任意版本跨度无缝同步**：支持客户端离线落后多个版本后的全量/增量自动追平与自愈。

### 5. 🔑 服务端全权加解密与一键私钥轮换
- **Fail-Closed 安全架构**：数据库仅存储 `AES-256-GCM` 密文、随机 `IV` 与独立 `Salt`，杜绝任何明文落地；
- **一键私钥更换 (Key Rotation)**：一键在线生成/指定新主私钥，服务端原子解密存量数据并全量重新加密写入；
- **加密备份导入导出**：支持导出含主私钥、密码记录及 SHA-256 校验和的 JSON 文件，导入时支持指定全新私钥。

### 6. 📱 Android 永久签名一致性与应用内 OTA 更新
- **永久密钥库签名**：内置专用 PKCS12 密钥库（有效期至 2054 年），Debug 与 Release 统一签名证书，确保应用升级无缝覆盖安装；
- **应用内检查更新与安装**：在 APP 设置中一键检测服务端最新 APK，通过 `FileProvider` 安全下载并调起系统安装；
- **内存安全擦除**：密钥派生与加解密完成后立即调用 `Arrays.fill(bytes, 0)` 零化敏感内存。

---

## 📂 项目目录结构

```
PwdManager/
├── android/                      # Android 原生客户端源码 (Java + AndroidX)
│   ├── app/
│   │   ├── pwdmanager.keystore   # 专用永久签名密钥库 (RSA 2048, SHA-256 证书)
│   │   ├── src/main/AndroidManifest.xml
│   │   ├── src/main/java/com/pwdmanager/app/
│   │   │   ├── model/            # 数据模型 (PasswordItem)
│   │   │   ├── db/               # 本地 SQLite 缓存与排重 (PasswordDatabaseHelper)
│   │   │   ├── network/          # 网络通信与鉴权 (ApiClient, SyncManager)
│   │   │   ├── crypto/           # 内存安全加解密工具 (CryptoUtils)
│   │   │   └── ui/               # 界面交互 (MainActivity, PasswordAdapter)
│   │   └── src/main/res/         # UI 布局、样式及矢量图标
│   ├── build.gradle              # Gradle 统一签名与构建配置
│   └── settings.gradle
├── server/                       # 服务端源码与测试套件
│   ├── app.py                    # REST API 服务端、防暴破引擎与 Web 控制台
│   ├── test_server.py            # 17 项全自动化综合安全与并发测试套件
│   └── download/                 # 客户端 APK 分发目录
├── dist/                         # 自动化打包输出目录 (由 build_all.sh 生成)
│   ├── PwdManager.apk            # 编译完成的安卓客户端安装包
│   ├── pwdmanager-server.tar.gz  # 服务端独立安装包
│   ├── install_server.sh         # 服务端一键独立安装脚本
│   └── uninstall_server.sh       # 服务端一键卸载脚本
├── build_all.sh                  # 🔨 一键编译打包脚本
└── README.md                     # 项目说明文档
```

---

## 📡 API 接口参考

| 路由 / 路径 | 方法 | 权限 | 说明 |
| :--- | :--- | :--- | :--- |
| `/` 或 `/admin` | `GET` | 公开 | 访问星空主题 Web 管理控制台 |
| `/download/app.apk` | `GET` | 公开 | 下载安卓客户端 APK 安装包 |
| `/api/health` | `GET` | 公开 | 服务端健康状态与加固标识检查 |
| `/api/auth/login` | `POST` | 公开 | 用户登录鉴权（支持双维度防暴破与时序防御） |
| `/api/auth/me` | `GET` | 需鉴权 | 获取当前登录管理员账号与角色 |
| `/api/auth/change-password`| `POST` | 需鉴权 | 修改当前管理员密码并即时轮换 Token |
| `/api/passwords` | `GET` | 需鉴权 | 获取密码记录列表（支持 `?decrypt=1` 服务端解密） |
| `/api/passwords` | `POST` | 需鉴权 | 创建新密码记录（**严格按名称排重**，服务端 AES-256 加密） |
| `/api/passwords/{id}` | `PUT` | 需鉴权 | 乐观锁原子更新密码记录（需传入 `version`，支持名称防重） |
| `/api/passwords/{id}` | `DELETE`| 需鉴权 | 软删除密码记录（递增全局版本号） |
| `/api/passwords/sync` | `POST` | 需鉴权 | 多端 64 位版本号仲裁与双向增量同步（支持同名自动归并） |
| `/api/admin/key` | `GET/POST`| Admin | 查看或更新服务端当前主私钥 |
| `/api/admin/rotate-key` | `POST` | Admin | **一键更换私钥**（原子解密并使用新私钥全量重加密） |
| `/api/admin/export` | `GET` | Admin | **一键导出**私钥与全部密码记录（含 SHA-256 校验和） |
| `/api/admin/import` | `POST` | Admin | **一键导入**密码记录并支持**指定全新私钥** |
| `/api/admin/security-logs`| `GET` | Admin | **查询安全审计日志**（失败统计、封禁列表与明细） |
| `/api/admin/security-logs/unlock`| `POST`| Admin | **解除目标封禁锁定**（解封指定 IP 或账号） |
| `/api/admin/security-logs`| `DELETE`| Admin | **清空安全审计日志** |

---

## 🔒 安全加密设计原理

1. **认证加密 (AEAD - AES-256-GCM)**：
   采用 `AES-256-GCM (Galois/Counter Mode)`，每次加密生成唯一的 12 字节初始化向量（IV），并附加 128 位认证标签（Auth Tag），有效防御密文篡改与重放攻击。
2. **高强度密钥派生 (PBKDF2-HMAC-SHA256)**：
   管理员密码认证采用 **100,000 次** PBKDF2 迭代与 16 字节随机盐；主加密密钥派生采用 **65,536 次** PBKDF2 迭代，确保密钥空间抗离线 GPU 暴力破解。
3. **OWASP Web 安全防护体系**：
   - 严格响应头：`Content-Security-Policy (CSP)`、`X-Frame-Options: DENY`（防点击劫持）、`X-Content-Type-Options: nosniff`、`Strict-Transport-Security (HSTS)`；
   - 跨域安全：严格遵循 RFC 1918 私网与同源匹配原则，杜绝通配符跨域数据泄露；
   - 传输安全：仅支持 HTTP Header 鉴权（`Authorization: Bearer <token>`），彻底杜绝 URL 查询参数泄露 Token。

---

## 🧪 自动化测试验证

项目包含一套由 17 个测试步骤构成的全自动化验证测试套件（`server/test_server.py`），覆盖：
1. OWASP 安全响应头校验
2. PBKDF2 密码哈希与认证
3. 严格 Header-Only Token 鉴权
4. 服务端 AES-256-GCM 加密与解密
5. 双向增量数据同步
6. 导出与指定私钥导入
7. 在线私钥轮转与批量重加密验证
8. 管理员修改密码与 Token 刷新
9. **网站/应用名称唯一性排重校验 (409 Conflict)**
10. **64 位全局版本号与乐观锁 (OCC) 冲突检测**
11. **多客户端高并发读写与竞态条件自愈压力测试**
12. **双维度防暴力破解、429 锁定与防时序攻击屏障测试**
13. **安全审计日志记录、异常 IP 追踪与管理接口测试**

运行自动化测试：
```bash
python3 server/test_server.py http://127.0.0.1:8000
```
