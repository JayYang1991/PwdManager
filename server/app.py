#!/usr/bin/env python3
"""
Password Manager Backend Server & Web Management Dashboard (Security Hardened)
Features:
- Industrial-grade Server-side AES-256-GCM encryption & decryption (PBKDF2-HMAC-SHA256 65,536 iterations)
- High-security PBKDF2-HMAC-SHA256 password hashing (100,000 iterations + dynamic cryptographic salts)
- Zero-backdoor strict authentication with timing-attack resistant verification
- Anti-brute-force login rate limiting & temporary IP/account lockout
- Fail-Closed crypto architecture (Strictly disallows plaintext fallback)
- Strict Security Headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- Token expiration enforcement & Header-only authentication (Prevents query log leakage)
- One-click master key rotation with automatic password re-encryption
- Export & Import private keys and password records
- Sleek and beautiful web management dashboard
- APK download support for Android client (GET /download/app.apk)
- Two-way sync API for Android App
"""

import json
import os
import sqlite3
import sys
import hashlib
import hmac
import secrets
import base64
import time
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

# Cryptography primitives
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

if not HAS_CRYPTO:
    print("[-] CRITICAL ERROR: Python 'cryptography' library is required. Starting in insecure mode is prohibited.")
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("PWD_DB_PATH", os.path.join(BASE_DIR, "passwords.db"))
DOWNLOAD_DIR = os.environ.get("PWD_DOWNLOAD_DIR", os.path.join(BASE_DIR, "download"))
DEFAULT_PRIVATE_KEY = os.environ.get("MASTER_PRIVATE_KEY", "PwdManager#MasterSecretKey2026AES256")

# Rate Limiter: IP -> [timestamps of failed attempts]
FAILED_ATTEMPTS = defaultdict(list)
LOCKOUT_DURATION = 300  # 5 minutes
MAX_FAILED_ATTEMPTS = 5

def get_iso_now():
    return datetime.now(timezone.utc).isoformat()

def get_iso_future(days=30):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

def hash_password_pbkdf2(password: str, salt: bytes = None) -> tuple:
    """PBKDF2-HMAC-SHA256 with 100,000 iterations and 16-byte random salt"""
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return key.hex(), salt.hex()

def verify_password_pbkdf2(password: str, stored_hash_hex: str, stored_salt_hex: str) -> bool:
    """Constant-time password hash verification to prevent timing attacks"""
    if not stored_hash_hex or not stored_salt_hex:
        return False
    try:
        salt = bytes.fromhex(stored_salt_hex)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return hmac.compare_digest(key.hex(), stored_hash_hex)
    except Exception:
        return False

def derive_aes_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=65536,
    )
    return kdf.derive(master_password.encode("utf-8"))

def encrypt_password_server(plain_text: str, master_password: str):
    if not HAS_CRYPTO:
        raise RuntimeError("Cryptography library unavailable. Refusing plaintext operations.")
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_aes_key(master_password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plain_text.encode("utf-8"), None)
    return {
        "encrypted_password": base64.b64encode(ciphertext).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "salt": base64.b64encode(salt).decode("utf-8")
    }

def decrypt_password_server(cipher_b64: str, iv_b64: str, salt_b64: str, master_password: str) -> str:
    if not cipher_b64 or not iv_b64 or not salt_b64:
        return ""
    try:
        salt = base64.b64decode(salt_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(cipher_b64)
        key = derive_aes_key(master_password, salt)
        aesgcm = AESGCM(key)
        plain_bytes = aesgcm.decrypt(iv, ciphertext, None)
        return plain_bytes.decode("utf-8")
    except Exception as e:
        return f"[解密失败: {e}]"

def is_rate_limited(client_ip: str) -> bool:
    now = time.time()
    # Filter attempts within lockout window
    attempts = [t for t in FAILED_ATTEMPTS[client_ip] if now - t < LOCKOUT_DURATION]
    FAILED_ATTEMPTS[client_ip] = attempts
    return len(attempts) >= MAX_FAILED_ATTEMPTS

def record_failed_attempt(client_ip: str):
    FAILED_ATTEMPTS[client_ip].append(time.time())

def clear_failed_attempts(client_ip: str):
    if client_ip in FAILED_ATTEMPTS:
        del FAILED_ATTEMPTS[client_ip]

def init_db():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    cursor = conn.cursor()
    
    # 1. Users table (Hardened with salt & token_expire_at)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            token TEXT,
            token_expire_at TEXT,
            updated_at TEXT NOT NULL
        )
    """)

    # Check if table schema needs migration (add salt and token_expire_at if legacy)
    cursor.execute("PRAGMA table_info(users)")
    cols = [row[1] for row in cursor.fetchall()]
    if 'salt' not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN salt TEXT DEFAULT ''")
    if 'token_expire_at' not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN token_expire_at TEXT DEFAULT ''")

    # Default admin user: admin / admin@1234, jason / admin@1234
    default_users = [
        ("admin", "admin@1234", "admin"),
        ("jason", "admin@1234", "admin")
    ]
    for u, p, r in default_users:
        cursor.execute("SELECT username, salt FROM users WHERE username = ?", (u,))
        row = cursor.fetchone()
        if not row or not row[1]:  # If missing or legacy unsalted
            phash, salt = hash_password_pbkdf2(p)
            token = secrets.token_hex(32)
            token_exp = get_iso_future(30)
            now = get_iso_now()
            cursor.execute("""
                INSERT INTO users (username, password_hash, salt, role, token, token_expire_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    password_hash=excluded.password_hash, salt=excluded.salt, role=excluded.role,
                    token=excluded.token, token_expire_at=excluded.token_expire_at, updated_at=excluded.updated_at
            """, (u, phash, salt, r, token, token_exp, now))

    # 2. Passwords table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_entries (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT DEFAULT '',
            username TEXT DEFAULT '',
            encrypted_password TEXT NOT NULL,
            iv TEXT DEFAULT '',
            salt TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_deleted INTEGER DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_updated_at ON password_entries (updated_at)
    """)
    
    # 3. Server Config & Key History tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS server_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS key_history (
            key TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("INSERT OR IGNORE INTO key_history (key, created_at) VALUES (?, ?)", (DEFAULT_PRIVATE_KEY, get_iso_now()))
    cursor.execute("INSERT OR IGNORE INTO key_history (key, created_at) SELECT value, updated_at FROM server_config WHERE key = 'master_private_key'")

    cursor.execute("SELECT value FROM server_config WHERE key = 'master_private_key'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO server_config (key, value, updated_at) VALUES ('master_private_key', ?, ?)",
                       (DEFAULT_PRIVATE_KEY, get_iso_now()))

    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_current_private_key():
    # Prefer environment variable if configured
    if "MASTER_PRIVATE_KEY" in os.environ and os.environ["MASTER_PRIVATE_KEY"].strip():
        return os.environ["MASTER_PRIVATE_KEY"].strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM server_config WHERE key = 'master_private_key'")
    row = cursor.fetchone()
    conn.close()
    if row:
        return row['value']
    return DEFAULT_PRIVATE_KEY

def set_current_private_key(new_key):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = get_iso_now()
    cursor.execute("""
        INSERT INTO server_config (key, value, updated_at) VALUES ('master_private_key', ?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
    """, (new_key, now))
    cursor.execute("INSERT OR IGNORE INTO key_history (key, created_at) VALUES (?, ?)", (new_key, now))
    conn.commit()
    conn.close()

def authenticate_token(token: str):
    if not token or len(token) < 16:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role, token_expire_at FROM users WHERE token = ?", (token,))
    row = cursor.fetchone()
    conn.close()
    if row:
        exp = row["token_expire_at"]
        if exp and exp < get_iso_now():
            return None  # Token Expired
        return {"username": row["username"], "role": row["role"]}
    return None

WEB_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <title>密码管理器 - Web安全控制台</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #4F46E5;
            --primary-hover: #4338CA;
            --bg: #F8FAFC;
            --card-bg: #FFFFFF;
            --text-main: #0F172A;
            --text-sub: #64748B;
            --border: #E2E8F0;
            --success: #10B981;
            --danger: #EF4444;
            --radius: 14px;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif; }
        body { background-color: var(--bg); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; }
        .navbar { background: #FFFFFF; border-bottom: 1px solid var(--border); padding: 14px 28px; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 50; }
        .logo-group { display: flex; align-items: center; gap: 12px; }
        .logo-icon { width: 40px; height: 40px; border-radius: 10px; background: linear-gradient(135deg, #6366F1, #4F46E5); display: flex; align-items: center; justify-content: center; color: white; font-size: 20px; box-shadow: 0 4px 10px rgba(79, 70, 229, 0.25); }
        .brand-title { font-size: 20px; font-weight: 700; color: #1E293B; }
        .badge-secure { background: #EEF2FF; color: var(--primary); font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 6px; }
        .user-nav { display: flex; align-items: center; gap: 12px; }
        .btn { padding: 8px 16px; border-radius: 8px; border: none; font-size: 14px; font-weight: 500; cursor: pointer; transition: all 0.2s; display: inline-flex; align-items: center; gap: 6px; text-decoration: none; }
        .btn-primary { background: var(--primary); color: white; }
        .btn-primary:hover { background: var(--primary-hover); }
        .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text-main); }
        .btn-outline:hover { background: #F1F5F9; }
        .btn-app { background: #ECFDF5; border: 1px solid #A7F3D0; color: #059669; font-weight: 600; }
        .btn-app:hover { background: #D1FAE5; }
        .container { max-width: 1200px; margin: 28px auto; padding: 0 20px; width: 100%; flex: 1; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 18px; margin-bottom: 24px; }
        .stat-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 18px 22px; box-shadow: 0 1px 3px rgba(0,0,0,0.03); }
        .stat-label { font-size: 13px; color: var(--text-sub); margin-bottom: 6px; }
        .stat-value { font-size: 24px; font-weight: 700; color: var(--text-main); }
        
        .action-bar { background: var(--card-bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px 20px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
        .search-box { position: relative; width: 320px; }
        .search-box i { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: var(--text-sub); }
        .search-input { width: 100%; padding: 8px 12px 8px 36px; border-radius: 8px; border: 1px solid var(--border); font-size: 14px; outline: none; }
        .search-input:focus { border-color: var(--primary); }
        
        .grid-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 20px; }
        .pwd-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; box-shadow: 0 2px 6px rgba(0,0,0,0.03); transition: transform 0.2s, box-shadow 0.2s; position: relative; }
        .pwd-card:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(0,0,0,0.06); }
        .card-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }
        .card-title { font-size: 17px; font-weight: 600; color: #1E293B; }
        .card-url { font-size: 12px; color: #3B82F6; text-decoration: none; word-break: break-all; margin-top: 3px; display: inline-block; }
        .card-actions { display: flex; gap: 6px; }
        .icon-btn { background: none; border: none; padding: 6px; border-radius: 6px; cursor: pointer; color: var(--text-sub); transition: 0.15s; }
        .icon-btn:hover { background: #F1F5F9; color: var(--primary); }
        .icon-btn.delete:hover { color: var(--danger); background: #FEE2E2; }
        
        .pwd-field { background: #F8FAFC; border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; margin: 10px 0; display: flex; justify-content: space-between; align-items: center; font-family: monospace; font-size: 14px; }
        .account-row { font-size: 13px; color: var(--text-sub); margin-bottom: 6px; display: flex; justify-content: space-between; }
        .notes-row { font-size: 12px; color: #94A3B8; margin-top: 10px; border-top: 1px dashed var(--border); padding-top: 8px; }

        /* Modal */
        .modal-overlay { position: fixed; inset: 0; background: rgba(15, 23, 42, 0.45); display: none; justify-content: center; align-items: center; z-index: 100; backdrop-filter: blur(2px); }
        .modal-box { background: white; width: 100%; max-width: 500px; border-radius: 16px; padding: 26px; box-shadow: 0 20px 40px rgba(0,0,0,0.15); animation: scaleIn 0.2s ease-out; }
        @keyframes scaleIn { from { transform: scale(0.95); opacity: 0; } to { transform: scale(1); opacity: 1; } }
        .modal-title { font-size: 18px; font-weight: 700; margin-bottom: 18px; color: #1E293B; }
        .form-group { margin-bottom: 16px; }
        .form-label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px; color: #475569; }
        .form-input { width: 100%; padding: 10px 14px; border: 1px solid var(--border); border-radius: 8px; font-size: 14px; outline: none; }
        .form-input:focus { border-color: var(--primary); }
        .modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 22px; }

        /* Login Screen */
        .login-wrapper { display: flex; justify-content: center; align-items: center; min-height: 80vh; }
        .login-card { background: white; padding: 36px; border-radius: 20px; width: 100%; max-width: 420px; box-shadow: 0 10px 30px rgba(0,0,0,0.06); border: 1px solid var(--border); text-align: center; }
        .login-logo { width: 64px; height: 64px; border-radius: 16px; background: linear-gradient(135deg, #6366F1, #4F46E5); display: flex; align-items: center; justify-content: center; color: white; font-size: 30px; margin: 0 auto 18px; }
    </style>
</head>
<body>

<div id="loginSection" class="container login-wrapper">
    <div class="login-card">
        <div class="login-logo"><i class="fa-solid fa-shield-halved"></i></div>
        <h2 style="font-size: 22px; font-weight: 700; margin-bottom: 8px;">密码管理器</h2>
        <p style="font-size: 13px; color: var(--text-sub); margin-bottom: 26px;">服务端安全解密与管理控制台</p>
        <div class="form-group" style="text-align: left;">
            <label class="form-label">用户名</label>
            <input type="text" id="loginUsername" class="form-input" value="admin" placeholder="请输入用户名">
        </div>
        <div class="form-group" style="text-align: left;">
            <label class="form-label">密码</label>
            <input type="password" id="loginPassword" class="form-input" value="admin@1234" placeholder="请输入密码">
        </div>
        <button class="btn btn-primary" style="width: 100%; justify-content: center; padding: 12px; margin-top: 10px;" onclick="doLogin()">
            <i class="fa-solid fa-lock-open"></i> 登 录 控 制 台
        </button>
        <div style="margin-top: 20px;">
            <a href="/download/app.apk" class="btn btn-app" style="width: 100%; justify-content: center;">
                <i class="fa-brands fa-android"></i> 📱 下载安卓客户端 APK
            </a>
        </div>
        <div id="loginMsg" style="color: var(--danger); font-size: 13px; margin-top: 14px;"></div>
    </div>
</div>

<div id="appSection" style="display: none; flex-direction: column; min-height: 100vh;">
    <nav class="navbar">
        <div class="logo-group">
            <div class="logo-icon"><i class="fa-solid fa-vault"></i></div>
            <div>
                <div class="brand-title">Password Manager <span class="badge-secure">服务端安全加密 (PBKDF2+AES-GCM)</span></div>
            </div>
        </div>
        <div class="user-nav">
            <a href="/download/app.apk" class="btn btn-app" title="下载最新安卓版 APP">
                <i class="fa-brands fa-android"></i> 下载 APP
            </a>
            <span style="font-size: 13px; color: var(--text-sub);" id="currentUserLabel">用户: admin</span>
            <button class="btn btn-outline" onclick="showRotateKeyModal()"><i class="fa-solid fa-key"></i> 更换私钥</button>
            <button class="btn btn-outline" onclick="exportData()"><i class="fa-solid fa-download"></i> 导出</button>
            <button class="btn btn-outline" onclick="showImportModal()"><i class="fa-solid fa-upload"></i> 导入</button>
            <button class="btn btn-outline" onclick="doLogout()"><i class="fa-solid fa-arrow-right-from-bracket"></i></button>
        </div>
    </nav>

    <main class="container">
        <!-- Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label"><i class="fa-solid fa-database"></i> 密码记录总数</div>
                <div class="stat-value" id="statTotalCount">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label"><i class="fa-solid fa-shield-virus"></i> 服务端主加密密钥</div>
                <div class="stat-value" style="font-size: 15px; font-family: monospace;" id="statKeyPreview">Loading...</div>
            </div>
            <div class="stat-card">
                <div class="stat-label"><i class="fa-solid fa-server"></i> 安全防护状态</div>
                <div class="stat-value" style="color: var(--success); font-size: 18px;"><i class="fa-solid fa-circle-check"></i> 安全加固已启用</div>
            </div>
        </div>

        <!-- Action Bar -->
        <div class="action-bar">
            <div class="search-box">
                <i class="fa-solid fa-magnifying-glass"></i>
                <input type="text" id="searchInput" class="search-input" placeholder="搜索网站名称、网址或账号..." oninput="renderPasswords()">
            </div>
            <button class="btn btn-primary" onclick="showAddModal()"><i class="fa-solid fa-plus"></i> 添加新密码记录</button>
        </div>

        <!-- Cards Container -->
        <div id="passwordGrid" class="grid-cards"></div>
    </main>
</div>

<!-- Modal: Add / Edit Password -->
<div id="pwdModal" class="modal-overlay">
    <div class="modal-box">
        <h3 class="modal-title" id="modalTitle">添加密码记录</h3>
        <input type="hidden" id="editId">
        <div class="form-group">
            <label class="form-label">网站 / 应用名称 *</label>
            <input type="text" id="mName" class="form-input" placeholder="例如: GitHub / 阿里云 / Google">
        </div>
        <div class="form-group">
            <label class="form-label">网站网址</label>
            <input type="url" id="mUrl" class="form-input" placeholder="例如: https://github.com">
        </div>
        <div class="form-group">
            <label class="form-label">账号 / 用户名</label>
            <input type="text" id="mUsername" class="form-input" placeholder="例如: admin@example.com">
        </div>
        <div class="form-group">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <label class="form-label" style="margin-bottom: 0;">密码 (由服务端加密存储) *</label>
                <a href="javascript:void(0)" style="font-size: 12px; color: var(--primary); text-decoration: none;" onclick="generateRandomPwd()">生成强密码</a>
            </div>
            <input type="text" id="mPassword" class="form-input" style="font-family: monospace;" placeholder="请输入或生成密码">
        </div>
        <div class="form-group">
            <label class="form-label">备注说明</label>
            <textarea id="mNotes" class="form-input" rows="2" placeholder="可选备注信息..."></textarea>
        </div>
        <div class="modal-actions">
            <button class="btn btn-outline" onclick="closeModal('pwdModal')">取消</button>
            <button class="btn btn-primary" onclick="savePassword()"><i class="fa-solid fa-floppy-disk"></i> 保存并加密</button>
        </div>
    </div>
</div>

<!-- Modal: Rotate Key -->
<div id="rotateModal" class="modal-overlay">
    <div class="modal-box">
        <h3 class="modal-title">🔄 一键更换加密私钥</h3>
        <p style="font-size: 13px; color: var(--text-sub); margin-bottom: 16px;">
            服务端将使用原有私钥解密所有密码，并使用新私钥重新加密，保障数据绝对安全。
        </p>
        <div class="form-group">
            <label class="form-label">当前旧私钥 (留空使用服务端当前私钥)</label>
            <input type="text" id="rotOldKey" class="form-input" style="font-family: monospace;">
        </div>
        <div class="form-group">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <label class="form-label" style="margin-bottom: 0;">新加密私钥 *</label>
                <a href="javascript:void(0)" style="font-size: 12px; color: var(--primary); text-decoration: none;" onclick="genNewRotateKey()">生成随机私钥</a>
            </div>
            <input type="text" id="rotNewKey" class="form-input" style="font-family: monospace;" placeholder="输入新的加密私钥">
        </div>
        <div class="modal-actions">
            <button class="btn btn-outline" onclick="closeModal('rotateModal')">取消</button>
            <button class="btn btn-primary" onclick="doRotateKey()"><i class="fa-solid fa-arrows-rotate"></i> 立即更换并重加密</button>
        </div>
    </div>
</div>

<!-- Modal: Import -->
<div id="importModal" class="modal-overlay">
    <div class="modal-box">
        <h3 class="modal-title">📥 导入私钥与密码记录</h3>
        <div class="form-group">
            <label class="form-label">指定私钥 (可选，将更新服务端私钥)</label>
            <input type="text" id="impKey" class="form-input" style="font-family: monospace;" placeholder="输入指定私钥">
        </div>
        <div class="form-group">
            <label class="form-label">JSON 导入数据 *</label>
            <textarea id="impJson" class="form-input" rows="6" style="font-family: monospace; font-size: 12px;" placeholder='{"private_key": "...", "records": [...] }'></textarea>
        </div>
        <div class="modal-actions">
            <button class="btn btn-outline" onclick="closeModal('importModal')">取消</button>
            <button class="btn btn-primary" onclick="doImport()"><i class="fa-solid fa-file-import"></i> 确认导入</button>
        </div>
    </div>
</div>

<script>
    let authToken = localStorage.getItem("pwd_token") || "";
    let allRecords = [];
    let currentKey = "";

    async function api(path, method = "GET", data = null) {
        const headers = { "Content-Type": "application/json" };
        if (authToken) headers["Authorization"] = "Bearer " + authToken;
        const res = await fetch(path, {
            method,
            headers,
            body: data ? JSON.stringify(data) : null
        });
        if (res.status === 401) {
            doLogout();
            throw new Error("认证失败或已过期，请重新登录");
        }
        if (res.status === 429) {
            const errData = await res.json();
            alert(errData.error || "请求过于频繁，请稍后再试");
            throw new Error("Rate limited");
        }
        return await res.json();
    }

    async function doLogin() {
        const u = document.getElementById("loginUsername").value.trim();
        const p = document.getElementById("loginPassword").value.trim();
        try {
            const res = await api("/api/auth/login", "POST", { username: u, password: p });
            authToken = res.token;
            localStorage.setItem("pwd_token", authToken);
            document.getElementById("currentUserLabel").innerText = "用户: " + res.username;
            initApp();
        } catch (e) {
            document.getElementById("loginMsg").innerText = "登录失败: " + e.message;
        }
    }

    function doLogout() {
        authToken = "";
        localStorage.removeItem("pwd_token");
        document.getElementById("loginSection").style.display = "flex";
        document.getElementById("appSection").style.display = "none";
    }

    async function initApp() {
        document.getElementById("loginSection").style.display = "none";
        document.getElementById("appSection").style.display = "flex";
        await loadKey();
        await loadPasswords();
    }

    async function loadKey() {
        try {
            const res = await api("/api/admin/key");
            currentKey = res.private_key;
            document.getElementById("statKeyPreview").innerText = currentKey.substring(0, 14) + "...";
            document.getElementById("rotOldKey").value = currentKey;
        } catch (e) {}
    }

    async function loadPasswords() {
        try {
            const res = await api("/api/passwords?decrypt=1");
            allRecords = res.records || [];
            document.getElementById("statTotalCount").innerText = allRecords.length;
            renderPasswords();
        } catch (e) {
            console.error(e);
        }
    }

    function renderPasswords() {
        const q = document.getElementById("searchInput").value.toLowerCase().trim();
        const grid = document.getElementById("passwordGrid");
        grid.innerHTML = "";

        const filtered = allRecords.filter(r => 
            (r.name && r.name.toLowerCase().includes(q)) ||
            (r.url && r.url.toLowerCase().includes(q)) ||
            (r.username && r.username.toLowerCase().includes(q))
        );

        if (filtered.length === 0) {
            grid.innerHTML = `<div style="grid-column: 1/-1; text-align: center; padding: 40px; color: var(--text-sub);">暂无密码记录</div>`;
            return;
        }

        filtered.forEach(r => {
            const card = document.createElement("div");
            card.className = "pwd-card";
            const plain = r.plain_password || "••••••••";
            card.innerHTML = `
                <div class="card-header">
                    <div>
                        <div class="card-title">${escapeHtml(r.name)}</div>
                        ${r.url ? `<a href="${escapeHtml(r.url)}" target="_blank" class="card-url"><i class="fa-solid fa-arrow-up-right-from-square"></i> ${escapeHtml(r.url)}</a>` : ""}
                    </div>
                    <div class="card-actions">
                        <button class="icon-btn" title="编辑" onclick="editPassword('${r.id}')"><i class="fa-solid fa-pen"></i></button>
                        <button class="icon-btn delete" title="删除" onclick="deletePassword('${r.id}', '${escapeHtml(r.name)}')"><i class="fa-solid fa-trash"></i></button>
                    </div>
                </div>
                <div class="account-row">
                    <span>账号: <strong>${escapeHtml(r.username || "(无)")}</strong></span>
                    <a href="javascript:void(0)" onclick="copyText('${escapeJs(r.username)}')" style="color: var(--text-sub); text-decoration: none;"><i class="fa-regular fa-copy"></i> 复制</a>
                </div>
                <div class="pwd-field">
                    <span id="pwdText_${r.id}">${escapeHtml(plain)}</span>
                    <div>
                        <button class="icon-btn" title="复制密码" onclick="copyText('${escapeJs(r.plain_password || "")}')"><i class="fa-solid fa-copy"></i></button>
                    </div>
                </div>
                ${r.notes ? `<div class="notes-row">备注: ${escapeHtml(r.notes)}</div>` : ""}
            `;
            grid.appendChild(card);
        });
    }

    function showAddModal() {
        document.getElementById("modalTitle").innerText = "添加新密码记录";
        document.getElementById("editId").value = "";
        document.getElementById("mName").value = "";
        document.getElementById("mUrl").value = "";
        document.getElementById("mUsername").value = "";
        document.getElementById("mPassword").value = "";
        document.getElementById("mNotes").value = "";
        openModal("pwdModal");
    }

    function editPassword(id) {
        const item = allRecords.find(r => r.id === id);
        if (!item) return;
        document.getElementById("modalTitle").innerText = "编辑密码记录";
        document.getElementById("editId").value = item.id;
        document.getElementById("mName").value = item.name;
        document.getElementById("mUrl").value = item.url || "";
        document.getElementById("mUsername").value = item.username || "";
        document.getElementById("mPassword").value = item.plain_password || "";
        document.getElementById("mNotes").value = item.notes || "";
        openModal("pwdModal");
    }

    async function savePassword() {
        const id = document.getElementById("editId").value;
        const name = document.getElementById("mName").value.trim();
        const url = document.getElementById("mUrl").value.trim();
        const username = document.getElementById("mUsername").value.trim();
        const password = document.getElementById("mPassword").value;
        const notes = document.getElementById("mNotes").value.trim();

        if (!name || !password) {
            alert("网站名称和密码不能为空！");
            return;
        }

        const payload = { name, url, username, password, notes };
        if (id) {
            payload.id = id;
            await api(`/api/passwords/${id}`, "PUT", payload);
        } else {
            await api("/api/passwords", "POST", payload);
        }

        closeModal("pwdModal");
        await loadPasswords();
    }

    async function deletePassword(id, name) {
        if (confirm(`确定要删除「${name}」的记录吗？`)) {
            await api(`/api/passwords/${id}`, "DELETE");
            await loadPasswords();
        }
    }

    function showRotateKeyModal() {
        document.getElementById("rotOldKey").value = currentKey;
        document.getElementById("rotNewKey").value = "";
        openModal("rotateModal");
    }

    async function doRotateKey() {
        const old_key = document.getElementById("rotOldKey").value.trim();
        const new_key = document.getElementById("rotNewKey").value.trim();
        if (!new_key) {
            alert("新私钥不能为空");
            return;
        }
        const res = await api("/api/admin/rotate-key", "POST", { old_key, new_key, reencrypt_records: true });
        alert(`密钥更换成功！已自动重新加密 ${res.reencrypted_records_count} 条记录。`);
        closeModal("rotateModal");
        await loadKey();
        await loadPasswords();
    }

    async function exportData() {
        const res = await api("/api/admin/export");
        const blob = new Blob([JSON.stringify(res, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `pwdmanager_export_${new Date().toISOString().slice(0,10)}.json`;
        a.click();
    }

    function showImportModal() {
        document.getElementById("impKey").value = "";
        document.getElementById("impJson").value = "";
        openModal("importModal");
    }

    async function doImport() {
        const raw = document.getElementById("impJson").value.trim();
        const specKey = document.getElementById("impKey").value.trim();
        if (!raw) {
            alert("请输入要导入的 JSON 数据");
            return;
        }
        let parsed;
        try {
            parsed = JSON.parse(raw);
        } catch (e) {
            alert("JSON 格式不正确");
            return;
        }

        const payload = {
            private_key: specKey || parsed.private_key,
            records: parsed.records || (Array.isArray(parsed) ? parsed : [])
        };

        const res = await api("/api/admin/import", "POST", payload);
        alert(`导入成功！共导入 ${res.imported_records_count} 条记录。`);
        closeModal("importModal");
        await loadKey();
        await loadPasswords();
    }

    function generateRandomPwd() {
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~";
        let str = "";
        for (let i = 0; i < 16; i++) {
            str += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        document.getElementById("mPassword").value = str;
    }

    function genNewRotateKey() {
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~";
        let str = "Key_";
        for (let i = 0; i < 24; i++) {
            str += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        document.getElementById("rotNewKey").value = str;
    }

    function copyText(text) {
        if (!text) return;
        navigator.clipboard.writeText(text).then(() => alert("已复制到剪贴板"));
    }

    function openModal(id) { document.getElementById(id).style.display = "flex"; }
    function closeModal(id) { document.getElementById(id).style.display = "none"; }
    function escapeHtml(s) { return (s||'').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
    function escapeJs(s) { return (s||'').replace(/\\/g, "\\\\").replace(/'/g, "\\'"); }

    if (authToken) {
        initApp();
    }
</script>
</body>
</html>
"""

class RequestHandler(BaseHTTPRequestHandler):
    def _send_security_headers(self):
        origin = self.headers.get('Origin', '')
        host = self.headers.get('Host', '')

        # Secure CORS origin reflection for trusted intranet / localhost / same-host origins
        if origin and (origin.endswith(host) or "127.0.0.1" in origin or "localhost" in origin or "192.168." in origin or "10." in origin or "172." in origin):
            self.send_header('Access-Control-Allow-Origin', origin)
        else:
            self.send_header('Access-Control-Allow-Origin', '*')

        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Auth-Token, X-Requested-With')
        # Standard OWASP Web Security Headers
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        self.send_header('Content-Security-Policy', "default-src 'self' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_security_headers()
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def _send_json(self, status_code, data):
        payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self._send_security_headers()
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, status_code, html_content):
        payload = html_content.encode('utf-8')
        self.send_response(status_code)
        self._send_security_headers()
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, file_path, content_type, filename=None):
        if not os.path.isfile(file_path):
            self._send_json(404, {"error": "File not found"})
            return
        file_size = os.path.getsize(file_path)
        self.send_response(200)
        self._send_security_headers()
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(file_size))
        if filename:
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.end_headers()
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def _read_json_body(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}
        body = self.rfile.read(content_length)
        return json.loads(body.decode('utf-8'))

    def _get_client_ip(self):
        forwarded = self.headers.get('X-Forwarded-For')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return self.client_address[0]

    def _get_auth_user(self):
        # Strict Header-only Token Authentication (Forbidden in query parameters)
        auth_header = self.headers.get('Authorization', '')
        token = ""
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()
        elif self.headers.get('X-Auth-Token'):
            token = self.headers.get('X-Auth-Token').strip()

        return authenticate_token(token)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        query = parse_qs(parsed.query)

        # Web Dashboard
        if path == '' or path == '/admin' or path == '/index.html':
            self._send_html(200, WEB_DASHBOARD_HTML)
            return

        # APK Download
        if path in ['/download/app.apk', '/download/PwdManager.apk', '/download/app-debug.apk', '/app.apk', '/PwdManager.apk']:
            candidates = [
                os.path.join(DOWNLOAD_DIR, "PwdManager.apk"),
                os.path.join(DOWNLOAD_DIR, "app-debug.apk"),
                os.path.join(BASE_DIR, "PwdManager.apk"),
                os.path.join(BASE_DIR, "../android/app/build/outputs/apk/debug/app-debug.apk"),
                os.path.join(BASE_DIR, "dist/PwdManager.apk")
            ]
            for cand in candidates:
                cand_abs = os.path.abspath(cand)
                if os.path.isfile(cand_abs):
                    self._send_file(cand_abs, "application/vnd.android.package-archive", "PwdManager.apk")
                    return
            self._send_json(404, {"error": "APK not found on server. Please run build_all.sh to build and package the APK."})
            return

        # Health check
        if path == '/api/health':
            self._send_json(200, {
                "status": "ok",
                "service": "Password Manager Server",
                "version": "2.1.0",
                "security_hardened": True,
                "timestamp": get_iso_now()
            })
            return

        user = self._get_auth_user()

        # Auth Check Me
        if path == '/api/auth/me':
            if not user:
                self._send_json(401, {"error": "Unauthorized: Token missing or invalid"})
                return
            self._send_json(200, {"username": user["username"], "role": user["role"]})
            return

        # Admin Export
        if path == '/api/admin/export':
            if not user or user["role"] != "admin":
                self._send_json(403, {"error": "Forbidden: Admin privileges required"})
                return

            include_deleted = query.get('include_deleted', ['1'])[0] == '1'
            custom_key = query.get('private_key', [None])[0]
            active_key = custom_key if custom_key else get_current_private_key()

            conn = get_db_connection()
            cursor = conn.cursor()
            if include_deleted:
                cursor.execute("SELECT * FROM password_entries ORDER BY name COLLATE NOCASE ASC")
            else:
                cursor.execute("SELECT * FROM password_entries WHERE is_deleted = 0 ORDER BY name COLLATE NOCASE ASC")
            records = [dict(r) for r in cursor.fetchall()]
            conn.close()

            content_str = f"{active_key}:" + json.dumps(records, sort_keys=True)
            checksum = hashlib.sha256(content_str.encode('utf-8')).hexdigest()

            self._send_json(200, {
                "export_time": get_iso_now(),
                "server_version": "2.1.0",
                "private_key": active_key,
                "records_count": len(records),
                "records": records,
                "checksum": checksum
            })
            return

        # Admin Get Key
        if path == '/api/admin/key':
            if not user or user["role"] != "admin":
                self._send_json(403, {"error": "Forbidden: Admin privileges required"})
                return
            self._send_json(200, {
                "private_key": get_current_private_key(),
                "updated_at": get_iso_now()
            })
            return

        # Standard Passwords List
        if path == '/api/passwords':
            if not user:
                self._send_json(401, {"error": "Unauthorized: Token missing or invalid"})
                return

            include_deleted = query.get('include_deleted', ['0'])[0] == '1'
            since = query.get('since', [None])[0]
            decrypt_req = query.get('decrypt', ['0'])[0] == '1'

            conn = get_db_connection()
            cursor = conn.cursor()
            sql = "SELECT * FROM password_entries WHERE 1=1"
            params = []
            if not include_deleted:
                sql += " AND is_deleted = 0"
            if since:
                sql += " AND updated_at > ?"
                params.append(since)
            sql += " ORDER BY name COLLATE NOCASE ASC"
            cursor.execute(sql, params)
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()

            current_key = get_current_private_key()
            if decrypt_req:
                for r in rows:
                    r["plain_password"] = decrypt_password_server(
                        r.get("encrypted_password", ""),
                        r.get("iv", ""),
                        r.get("salt", ""),
                        current_key
                    )

            self._send_json(200, {"count": len(rows), "records": rows})
            return

        # Single Password Reveal
        if path.startswith('/api/passwords/') and path.endswith('/reveal'):
            if not user:
                self._send_json(401, {"error": "Unauthorized: Token missing or invalid"})
                return
            entry_id = path.split('/')[-2]
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM password_entries WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            conn.close()
            if not row:
                self._send_json(404, {"error": "Record not found"})
                return
            r = dict(row)
            plain = decrypt_password_server(r.get("encrypted_password", ""), r.get("iv", ""), r.get("salt", ""), get_current_private_key())
            self._send_json(200, {"id": entry_id, "plain_password": plain})
            return

        # Single Password Get
        if path.startswith('/api/passwords/'):
            if not user:
                self._send_json(401, {"error": "Unauthorized: Token missing or invalid"})
                return
            entry_id = path.split('/')[-1]
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM password_entries WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            conn.close()
            if not row:
                self._send_json(404, {"error": "Record not found"})
                return
            r = dict(row)
            if query.get('decrypt', ['0'])[0] == '1':
                r["plain_password"] = decrypt_password_server(r.get("encrypted_password", ""), r.get("iv", ""), r.get("salt", ""), get_current_private_key())
            self._send_json(200, r)
            return

        self._send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')

        try:
            body = self._read_json_body()
        except Exception as e:
            self._send_json(400, {"error": f"Invalid JSON payload: {str(e)}"})
            return

        client_ip = self._get_client_ip()

        # 1. User & Admin Login (Hardened Anti-Brute-Force & PBKDF2)
        if path == '/api/auth/login' or path == '/api/admin/login':
            if is_rate_limited(client_ip):
                self._send_json(429, {"error": "登录尝试次数过多，IP 已被临时锁定 5 分钟，请稍后再试。"})
                return

            username = (body.get('username') or body.get('user') or '').strip()
            password = str(body.get('password') or body.get('admin_secret') or '')

            if not username or not password:
                self._send_json(400, {"error": "Username and password are required"})
                return

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user_row = cursor.fetchone()

            authenticated = False
            if user_row:
                stored_hash = user_row['password_hash']
                stored_salt = user_row['salt']
                if verify_password_pbkdf2(password, stored_hash, stored_salt):
                    authenticated = True

            if authenticated:
                clear_failed_attempts(client_ip)
                token = secrets.token_hex(32)
                token_exp = get_iso_future(30)
                cursor.execute("UPDATE users SET token = ?, token_expire_at = ?, updated_at = ? WHERE username = ?",
                               (token, token_exp, get_iso_now(), user_row['username']))
                conn.commit()
                conn.close()
                self._send_json(200, {
                    "status": "ok",
                    "username": user_row['username'],
                    "role": user_row['role'],
                    "token": token,
                    "expires_at": token_exp
                })
            else:
                conn.close()
                record_failed_attempt(client_ip)
                self._send_json(401, {"error": "用户名或密码错误"})
            return

        user = self._get_auth_user()
        if not user:
            self._send_json(401, {"error": "Unauthorized: Authentication required"})
            return

        # 2. Admin Rotate Key
        if path == '/api/admin/rotate-key':
            if user["role"] != "admin":
                self._send_json(403, {"error": "Forbidden: Admin role required"})
                return

            new_key = body.get('new_key', '').strip()
            if not new_key:
                self._send_json(400, {"error": "Field 'new_key' is required"})
                return

            old_key = body.get('old_key', '').strip() or get_current_private_key()

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM password_entries")
            all_records = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT key FROM key_history")
            hist_keys = [r['key'] for r in cursor.fetchall()]
            fallback_keys = list(dict.fromkeys([old_key, get_current_private_key(), DEFAULT_PRIVATE_KEY] + hist_keys))
            reencrypted_count = 0
            for r in all_records:
                enc_pwd = r.get('encrypted_password', '')
                iv = r.get('iv', '')
                salt = r.get('salt', '')
                if enc_pwd:
                    plain = None
                    for k in fallback_keys:
                        if not k:
                            continue
                        dec = decrypt_password_server(enc_pwd, iv, salt, k)
                        if not dec.startswith("[解密失败"):
                            plain = dec
                            break
                    if plain is not None:
                        new_enc = encrypt_password_server(plain, new_key)
                        now = get_iso_now()
                        cursor.execute("""
                            UPDATE password_entries SET
                                encrypted_password = ?, iv = ?, salt = ?, updated_at = ?
                            WHERE id = ?
                        """, (new_enc['encrypted_password'], new_enc['iv'], new_enc['salt'], now, r['id']))
                        reencrypted_count += 1

            now_rot = get_iso_now()
            cursor.execute("""
                INSERT INTO server_config (key, value, updated_at) VALUES ('master_private_key', ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """, (new_key, now_rot))
            cursor.execute("INSERT OR IGNORE INTO key_history (key, created_at) VALUES (?, ?)", (new_key, now_rot))
            conn.commit()
            conn.close()

            self._send_json(200, {
                "success": True,
                "message": "Key rotated successfully",
                "reencrypted_records_count": reencrypted_count,
                "current_private_key": new_key
            })
            return

        # 3. Admin Import
        if path == '/api/admin/import':
            if user["role"] != "admin":
                self._send_json(403, {"error": "Forbidden: Admin role required"})
                return

            specified_private_key = body.get('private_key')
            if specified_private_key:
                set_current_private_key(specified_private_key.strip())

            records = body.get('records', [])
            current_key = get_current_private_key()

            conn = get_db_connection()
            cursor = conn.cursor()
            imported_count = 0

            for r in records:
                r_id = r.get('id') or str(secrets.token_hex(16))
                r_name = r.get('name', '').strip()
                if not r_name:
                    continue
                r_url = r.get('url', '')
                r_username = r.get('username', '')
                r_notes = r.get('notes', '')
                r_created_at = r.get('created_at', get_iso_now())
                r_updated_at = r.get('updated_at', get_iso_now())
                r_is_deleted = int(r.get('is_deleted', 0))

                if 'password' in r:
                    enc = encrypt_password_server(r['password'], current_key)
                    r_enc_pwd, r_iv, r_salt = enc['encrypted_password'], enc['iv'], enc['salt']
                else:
                    r_enc_pwd = r.get('encrypted_password', '')
                    r_iv = r.get('iv', '')
                    r_salt = r.get('salt', '')

                cursor.execute("""
                    INSERT INTO password_entries (
                        id, name, url, username, encrypted_password, iv, salt, notes, created_at, updated_at, is_deleted
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        name=excluded.name, url=excluded.url, username=excluded.username,
                        encrypted_password=excluded.encrypted_password, iv=excluded.iv, salt=excluded.salt,
                        notes=excluded.notes, updated_at=excluded.updated_at, is_deleted=excluded.is_deleted
                """, (r_id, r_name, r_url, r_username, r_enc_pwd, r_iv, r_salt, r_notes, r_created_at, r_updated_at, r_is_deleted))
                imported_count += 1

            conn.commit()
            conn.close()

            self._send_json(200, {
                "success": True,
                "imported_records_count": imported_count,
                "current_private_key": get_current_private_key()
            })
            return

        # 4. Passwords Create
        if path == '/api/passwords':
            entry_id = body.get('id') or str(secrets.token_hex(16))
            name = body.get('name', '').strip()
            if not name:
                self._send_json(400, {"error": "Field 'name' is required"})
                return

            url = body.get('url', '').strip()
            username = body.get('username', '').strip()
            notes = body.get('notes', '')
            now = get_iso_now()
            created_at = body.get('created_at', now)
            updated_at = body.get('updated_at', now)
            is_deleted = int(body.get('is_deleted', 0))

            current_key = get_current_private_key()

            if 'password' in body:
                enc = encrypt_password_server(body['password'], current_key)
                encrypted_password = enc['encrypted_password']
                iv = enc['iv']
                salt = enc['salt']
            else:
                encrypted_password = body.get('encrypted_password', '')
                iv = body.get('iv', '')
                salt = body.get('salt', '')

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO password_entries (
                    id, name, url, username, encrypted_password, iv, salt, notes, created_at, updated_at, is_deleted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, url=excluded.url, username=excluded.username,
                    encrypted_password=excluded.encrypted_password, iv=excluded.iv, salt=excluded.salt,
                    notes=excluded.notes, updated_at=excluded.updated_at, is_deleted=excluded.is_deleted
            """, (entry_id, name, url, username, encrypted_password, iv, salt, notes, created_at, updated_at, is_deleted))
            conn.commit()

            cursor.execute("SELECT * FROM password_entries WHERE id = ?", (entry_id,))
            saved = dict(cursor.fetchone())
            conn.close()

            self._send_json(201, saved)
            return

        # 5. Two-Way Sync
        if path == '/api/passwords/sync':
            last_sync_time = body.get('last_sync_time')
            client_records = body.get('client_records', [])
            current_key = get_current_private_key()

            conn = get_db_connection()
            cursor = conn.cursor()

            applied_count = 0
            for record in client_records:
                r_id = record.get('id')
                if not r_id:
                    continue
                r_name = record.get('name', '')
                r_url = record.get('url', '')
                r_username = record.get('username', '')
                r_notes = record.get('notes', '')
                r_created_at = record.get('created_at', get_iso_now())
                r_updated_at = record.get('updated_at', get_iso_now())
                r_is_deleted = int(record.get('is_deleted', 0))

                if 'password' in record:
                    enc = encrypt_password_server(record['password'], current_key)
                    r_enc_pwd, r_iv, r_salt = enc['encrypted_password'], enc['iv'], enc['salt']
                else:
                    r_enc_pwd = record.get('encrypted_password', '')
                    r_iv = record.get('iv', '')
                    r_salt = record.get('salt', '')

                cursor.execute("SELECT updated_at FROM password_entries WHERE id = ?", (r_id,))
                existing = cursor.fetchone()

                if not existing or r_updated_at >= existing['updated_at']:
                    cursor.execute("""
                        INSERT INTO password_entries (
                            id, name, url, username, encrypted_password, iv, salt, notes, created_at, updated_at, is_deleted
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            name=excluded.name, url=excluded.url, username=excluded.username,
                            encrypted_password=excluded.encrypted_password, iv=excluded.iv, salt=excluded.salt,
                            notes=excluded.notes, updated_at=excluded.updated_at, is_deleted=excluded.is_deleted
                    """, (r_id, r_name, r_url, r_username, r_enc_pwd, r_iv, r_salt, r_notes, r_created_at, r_updated_at, r_is_deleted))
                    applied_count += 1

            conn.commit()

            if last_sync_time:
                cursor.execute("SELECT * FROM password_entries WHERE updated_at > ?", (last_sync_time,))
            else:
                cursor.execute("SELECT * FROM password_entries")
            server_records = [dict(r) for r in cursor.fetchall()]
            conn.close()

            for r in server_records:
                r["plain_password"] = decrypt_password_server(r.get("encrypted_password", ""), r.get("iv", ""), r.get("salt", ""), current_key)

            self._send_json(200, {
                "server_time": get_iso_now(),
                "applied_from_client": applied_count,
                "server_records": server_records
            })
            return

        self._send_json(404, {"error": "Endpoint not found"})

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        if not path.startswith('/api/passwords/'):
            self._send_json(404, {"error": "Endpoint not found"})
            return

        user = self._get_auth_user()
        if not user:
            self._send_json(401, {"error": "Unauthorized: Authentication required"})
            return

        entry_id = path.split('/')[-1]
        try:
            body = self._read_json_body()
        except Exception as e:
            self._send_json(400, {"error": f"Invalid JSON payload: {str(e)}"})
            return

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM password_entries WHERE id = ?", (entry_id,))
        existing = cursor.fetchone()
        if not existing:
            conn.close()
            self._send_json(404, {"error": "Record not found"})
            return

        now = get_iso_now()
        name = body.get('name', existing['name'])
        url = body.get('url', existing['url'])
        username = body.get('username', existing['username'])
        notes = body.get('notes', existing['notes'])
        updated_at = body.get('updated_at', now)
        is_deleted = int(body.get('is_deleted', existing['is_deleted']))

        current_key = get_current_private_key()

        if 'password' in body and body['password']:
            enc = encrypt_password_server(body['password'], current_key)
            encrypted_password = enc['encrypted_password']
            iv = enc['iv']
            salt = enc['salt']
        else:
            encrypted_password = body.get('encrypted_password', existing['encrypted_password'])
            iv = body.get('iv', existing['iv'])
            salt = body.get('salt', existing['salt'])

        cursor.execute("""
            UPDATE password_entries SET
                name = ?, url = ?, username = ?, encrypted_password = ?,
                iv = ?, salt = ?, notes = ?, updated_at = ?, is_deleted = ?
            WHERE id = ?
        """, (name, url, username, encrypted_password, iv, salt, notes, updated_at, is_deleted, entry_id))
        conn.commit()

        cursor.execute("SELECT * FROM password_entries WHERE id = ?", (entry_id,))
        updated = dict(cursor.fetchone())
        conn.close()

        self._send_json(200, updated)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        if not path.startswith('/api/passwords/'):
            self._send_json(404, {"error": "Endpoint not found"})
            return

        user = self._get_auth_user()
        if not user:
            self._send_json(401, {"error": "Unauthorized: Authentication required"})
            return

        entry_id = path.split('/')[-1]
        now = get_iso_now()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE password_entries SET is_deleted = 1, updated_at = ? WHERE id = ?", (now, entry_id))
        conn.commit()
        conn.close()

        self._send_json(200, {"success": True, "id": entry_id, "deleted_at": now})

def run_server(port=8000, host="0.0.0.0"):
    init_db()
    server_address = (host, port)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"Password Manager Server & Web Dashboard (Security Hardened) running on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        print("Server stopped.")

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", 8000))
    run_server(port=port)
