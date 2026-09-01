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
import threading
import sqlite3
import sys
import hashlib
import hmac
import secrets
import base64
import time
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
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

SERVER_VERSION = "v1.0.0"
GITHUB_REPO = "JayYang1991/PwdManager"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("PWD_DB_PATH", os.path.join(BASE_DIR, "passwords.db"))
DOWNLOAD_DIR = os.environ.get("PWD_DOWNLOAD_DIR", os.path.join(BASE_DIR, "download"))
DEFAULT_PRIVATE_KEY = os.environ.get("MASTER_PRIVATE_KEY", "PwdManager#MasterSecretKey2026AES256")
MAX_REQUEST_BODY_SIZE = 10 * 1024 * 1024  # 10 MB strict limit
TRUST_PROXY = os.environ.get("TRUST_PROXY", "0") == "1" 

# ==============================================================================
# 🛡️ Dual-Dimension Anti-Brute-Force Engine (IP + Account Level Protection)
# ==============================================================================
RATE_LIMIT_LOCK = threading.Lock()
FAILED_ATTEMPTS_IP = defaultdict(list)
FAILED_ATTEMPTS_USER = defaultdict(list)
LOCKOUT_DURATION = 300  # 5 minutes in seconds
MAX_FAILED_ATTEMPTS = 5

def check_rate_limit(client_ip: str, username: str = None) -> tuple:
    """
    Check if IP or Account (username) is currently locked out.
    Returns (is_locked: bool, retry_after_seconds: int, lock_reason: str)
    """
    now = time.time()
    with RATE_LIMIT_LOCK:
        # 1. Clean & check IP records
        ip_attempts = [t for t in FAILED_ATTEMPTS_IP[client_ip] if now - t < LOCKOUT_DURATION]
        FAILED_ATTEMPTS_IP[client_ip] = ip_attempts

        if len(ip_attempts) >= MAX_FAILED_ATTEMPTS:
            oldest_relevant = ip_attempts[-MAX_FAILED_ATTEMPTS]
            retry_after = max(1, int(LOCKOUT_DURATION - (now - oldest_relevant)))
            return True, retry_after, f"当前 IP 连续尝试失败已达 {MAX_FAILED_ATTEMPTS} 次，已触发安全锁定，请 {retry_after} 秒后再试。"

        # 2. Clean & check Username records if specified
        if username:
            u_key = username.strip().lower()
            user_attempts = [t for t in FAILED_ATTEMPTS_USER[u_key] if now - t < LOCKOUT_DURATION]
            FAILED_ATTEMPTS_USER[u_key] = user_attempts

            if len(user_attempts) >= MAX_FAILED_ATTEMPTS:
                oldest_relevant = user_attempts[-MAX_FAILED_ATTEMPTS]
                retry_after = max(1, int(LOCKOUT_DURATION - (now - oldest_relevant)))
                return True, retry_after, f"账号 '{username}' 连续登录失败超过 {MAX_FAILED_ATTEMPTS} 次，已触发临时安全保护锁定，请 {retry_after} 秒后再试。"

        # 3. Periodic memory garbage collection
        if len(FAILED_ATTEMPTS_IP) > 500:
            stale_ips = [ip for ip, atts in FAILED_ATTEMPTS_IP.items() if not atts or now - atts[-1] >= LOCKOUT_DURATION]
            for ip in stale_ips:
                FAILED_ATTEMPTS_IP.pop(ip, None)
        if len(FAILED_ATTEMPTS_USER) > 500:
            stale_users = [u for u, atts in FAILED_ATTEMPTS_USER.items() if not atts or now - atts[-1] >= LOCKOUT_DURATION]
            for u in stale_users:
                FAILED_ATTEMPTS_USER.pop(u, None)

        return False, 0, ""

def record_failed_attempt(client_ip: str, username: str = None) -> int:
    """
    Record a failed login attempt for both IP and username.
    Returns the number of remaining attempts before lockout.
    """
    now = time.time()
    with RATE_LIMIT_LOCK:
        FAILED_ATTEMPTS_IP[client_ip].append(now)
        ip_count = len([t for t in FAILED_ATTEMPTS_IP[client_ip] if now - t < LOCKOUT_DURATION])

        user_count = 0
        if username:
            u_key = username.strip().lower()
            FAILED_ATTEMPTS_USER[u_key].append(now)
            user_count = len([t for t in FAILED_ATTEMPTS_USER[u_key] if now - t < LOCKOUT_DURATION])

        max_used = max(ip_count, user_count)
        remaining = max(0, MAX_FAILED_ATTEMPTS - max_used)
        return remaining

def clear_failed_attempts(client_ip: str, username: str = None):
    """Clear failed attempt history upon successful authentication."""
    with RATE_LIMIT_LOCK:
        if client_ip:
            FAILED_ATTEMPTS_IP.pop(client_ip, None)
        if username:
            FAILED_ATTEMPTS_USER.pop(username.strip().lower(), None)

def get_active_lockouts() -> dict:
    """Return lists of currently locked out IPs and Users with remaining seconds."""
    now = time.time()
    locked_ips = []
    locked_users = []
    with RATE_LIMIT_LOCK:
        for ip, atts in FAILED_ATTEMPTS_IP.items():
            valid_atts = [t for t in atts if now - t < LOCKOUT_DURATION]
            if len(valid_atts) >= MAX_FAILED_ATTEMPTS:
                remaining = max(1, int(LOCKOUT_DURATION - (now - valid_atts[-MAX_FAILED_ATTEMPTS])))
                locked_ips.append({"ip": ip, "remaining_seconds": remaining, "failed_count": len(valid_atts)})

        for user, atts in FAILED_ATTEMPTS_USER.items():
            valid_atts = [t for t in atts if now - t < LOCKOUT_DURATION]
            if len(valid_atts) >= MAX_FAILED_ATTEMPTS:
                remaining = max(1, int(LOCKOUT_DURATION - (now - valid_atts[-MAX_FAILED_ATTEMPTS])))
                locked_users.append({"username": user, "remaining_seconds": remaining, "failed_count": len(valid_atts)})

    return {"locked_ips": locked_ips, "locked_users": locked_users}

def record_security_log(ip: str, username: str, user_agent: str, status: str, failure_reason: str):
    """Record security audit logs (failed logins, lockouts, successful logins) into database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA busy_timeout=5000;")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_audit_logs (ip, username_attempted, user_agent, status, failure_reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ip, username or 'unknown', user_agent[:255] if user_agent else '', status, failure_reason, get_iso_now()))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[-] Failed to record security audit log: {e}")

# Session Timeout Configuration (Inactivity expiration in minutes)
SESSION_TIMEOUT_MINUTES = int(os.environ.get("SESSION_TIMEOUT_MINUTES", "30"))

def get_iso_now():
    return datetime.now(timezone.utc).isoformat()

def get_iso_future(days=30):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

def get_iso_future_minutes(minutes=30):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()

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

# Legacy rate limiter replaced by dual-dimension engine

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



    # 1. Clean up legacy 'admin' user if primary administrator 'jason' is active
    cursor.execute("DELETE FROM users WHERE username = 'admin' AND EXISTS (SELECT 1 FROM users WHERE username = 'jason')")

    # 2. Initialize default primary admin (jason / admin@1234) if users table is empty
    cursor.execute("SELECT username, salt FROM users WHERE username = 'jason'")
    row = cursor.fetchone()
    if not row or not row[1]:  # If missing or legacy unsalted
        phash, salt = hash_password_pbkdf2("admin@1234")
        token = secrets.token_hex(32)
        token_exp = get_iso_future(30)
        now = get_iso_now()
        cursor.execute("""
            INSERT INTO users (username, password_hash, salt, role, token, token_expire_at, updated_at)
            VALUES ('jason', ?, ?, 'admin', ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                password_hash=excluded.password_hash, salt=excluded.salt, role=excluded.role,
                token=excluded.token, token_expire_at=excluded.token_expire_at, updated_at=excluded.updated_at
        """, (phash, salt, token, token_exp, now))

    # 4. Security Audit Logs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            username_attempted TEXT NOT NULL,
            user_agent TEXT DEFAULT '',
            status TEXT NOT NULL,
            failure_reason TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_logs_created ON security_audit_logs(created_at DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_logs_ip ON security_audit_logs(ip)")

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
            is_deleted INTEGER DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_updated_at ON password_entries (updated_at)
    """)

    cursor.execute("PRAGMA table_info(password_entries)")
    pwd_cols = [row[1] for row in cursor.fetchall()]
    if 'version' not in pwd_cols:
        cursor.execute("ALTER TABLE password_entries ADD COLUMN version INTEGER NOT NULL DEFAULT 0")
    
    # 3. Server Config & Key History tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS server_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        INSERT OR IGNORE INTO server_config (key, value, updated_at)
        VALUES ('global_version', '0', ?)
    """, (get_iso_now(),))
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
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn


def get_global_version(conn=None):
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM server_config WHERE key = 'global_version'")
    row = cursor.fetchone()
    if not row:
        now = get_iso_now()
        cursor.execute("INSERT OR IGNORE INTO server_config (key, value, updated_at) VALUES ('global_version', '0', ?)", (now,))
        conn.commit()
        ver = 0
    else:
        try:
            ver = int(row['value'])
        except Exception:
            ver = 0
    if close_conn:
        conn.close()
    return ver

def set_global_version(ver, conn=None):
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
    cursor = conn.cursor()
    now = get_iso_now()
    cursor.execute("""
        INSERT INTO server_config (key, value, updated_at) VALUES ('global_version', ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    """, (str(int(ver)), now))
    if close_conn:
        conn.commit()
        conn.close()
    return int(ver)

def increment_global_version(conn, expected_ver=None):
    cursor = conn.cursor()
    now = get_iso_now()
    if expected_ver is not None:
        cursor.execute("""
            UPDATE server_config
            SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT), updated_at = ?
            WHERE key = 'global_version' AND CAST(value AS INTEGER) = ?
        """, (now, int(expected_ver)))
        if cursor.rowcount == 0:
            cursor.execute("SELECT value FROM server_config WHERE key = 'global_version'")
            row = cursor.fetchone()
            current_ver = int(row['value']) if row else 0
            return False, current_ver
        cursor.execute("SELECT value FROM server_config WHERE key = 'global_version'")
        new_ver = int(cursor.fetchone()['value'])
        return True, new_ver
    else:
        cursor.execute("""
            INSERT INTO server_config (key, value, updated_at) VALUES ('global_version', '1', ?)
            ON CONFLICT(key) DO UPDATE SET
                value = CAST(CAST(value AS INTEGER) + 1 AS TEXT),
                updated_at = excluded.updated_at
        """, (now,))
        cursor.execute("SELECT value FROM server_config WHERE key = 'global_version'")
        new_ver = int(cursor.fetchone()['value'])
        return True, new_ver

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
    if not row:
        conn.close()
        return None
    
    exp = row["token_expire_at"]
    now_iso = get_iso_now()
    if exp and exp < now_iso:
        conn.close()
        return None  # Token Expired
    
    # Sliding Activity Expiration: Automatically extend active session by SESSION_TIMEOUT_MINUTES
    try:
        new_exp = get_iso_future_minutes(SESSION_TIMEOUT_MINUTES)
        cursor.execute("UPDATE users SET token_expire_at = ? WHERE token = ?", (new_exp, token))
        conn.commit()
    except Exception:
        pass
    conn.close()
    return {"username": row["username"], "role": row["role"]}

WEB_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta name="theme-color" content="#030712">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>星空密码管理器 - Web安全控制台</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --cosmic-bg: #030712;
            --nebula-1: #1E1B4B;
            --nebula-2: #0F172A;
            --primary: #818CF8;
            --primary-glow: rgba(129, 140, 248, 0.4);
            --accent-cyan: #38BDF8;
            --accent-pink: #F43F5E;
            --card-glass: rgba(15, 23, 42, 0.72);
            --card-border: rgba(255, 255, 255, 0.12);
            --card-hover-border: rgba(129, 140, 248, 0.5);
            --text-main: #F8FAFC;
            --text-sub: #94A3B8;
            --text-glow: 0 0 10px rgba(255, 255, 255, 0.2);
            --radius: 16px;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
            -webkit-tap-highlight-color: transparent;
        }
        body {
            background-color: var(--cosmic-bg);
            color: var(--text-main);
            min-height: 100vh;
            min-height: -webkit-fill-available;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
            position: relative;
            padding-top: env(safe-area-inset-top);
            padding-bottom: env(safe-area-inset-bottom);
        }
        
        /* Starfield Canvas Background */
        #starfield {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            z-index: 0;
            pointer-events: none;
        }
        
        /* Aurora / Nebula Ambient Gradients */
        .nebula-glow {
            position: fixed;
            top: -20%;
            left: 10%;
            width: 80vw;
            height: 60vh;
            background: radial-gradient(circle, rgba(99, 102, 241, 0.15) 0%, rgba(168, 85, 247, 0.1) 40%, transparent 70%);
            filter: blur(80px);
            z-index: 0;
            pointer-events: none;
            animation: nebulaFloat 18s ease-in-out infinite alternate;
        }
        @keyframes nebulaFloat {
            0% { transform: translate(0, 0) scale(1); }
            100% { transform: translate(5%, 10%) scale(1.1); }
        }

        /* Glass Navbar */
        .navbar {
            background: rgba(10, 15, 30, 0.8);
            border-bottom: 1px solid var(--card-border);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            padding: 12px 28px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 50;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
            transition: all 0.3s;
        }
        .logo-group {
            display: flex;
            align-items: center;
            gap: 12px;
            text-decoration: none;
        }
        .logo-icon {
            width: 40px;
            height: 40px;
            min-width: 40px;
            border-radius: 12px;
            background: linear-gradient(135deg, #6366F1, #A855F7, #EC4899);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 20px;
            box-shadow: 0 0 20px rgba(168, 85, 247, 0.5), inset 0 0 10px rgba(255, 255, 255, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.3);
            animation: pulseGlow 4s infinite alternate;
        }
        @keyframes pulseGlow {
            0% { box-shadow: 0 0 15px rgba(129, 140, 248, 0.4); }
            100% { box-shadow: 0 0 25px rgba(236, 72, 153, 0.6); }
        }
        .brand-title {
            font-size: 18px;
            font-weight: 700;
            color: #FFFFFF;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .badge-secure {
            background: rgba(129, 140, 248, 0.15);
            border: 1px solid rgba(129, 140, 248, 0.4);
            color: var(--accent-cyan);
            font-size: 11px;
            font-weight: 600;
            padding: 3px 8px;
            border-radius: 20px;
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.2);
            white-space: nowrap;
        }
        
        .user-nav-desktop {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }
        .user-nav-mobile {
            display: none;
            align-items: center;
            gap: 8px;
        }

        .btn {
            padding: 8px 16px;
            min-height: 38px;
            border-radius: 10px;
            border: none;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            text-decoration: none;
            white-space: nowrap;
            user-select: none;
        }
        .btn-primary {
            background: linear-gradient(135deg, #6366F1, #8B5CF6, #D946EF);
            color: white;
            box-shadow: 0 4px 15px rgba(139, 92, 246, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .btn-primary:hover, .btn-primary:active {
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(217, 70, 239, 0.6);
            background: linear-gradient(135deg, #4F46E5, #7C3AED, #C026D3);
        }
        .btn-outline {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--card-border);
            color: var(--text-main);
            backdrop-filter: blur(8px);
        }
        .btn-outline:hover, .btn-outline:active {
            background: rgba(30, 41, 59, 0.8);
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.3);
            transform: translateY(-1px);
        }
        .btn-app {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.2), rgba(6, 182, 212, 0.2));
            border: 1px solid rgba(16, 185, 129, 0.4);
            color: #34D399;
            font-weight: 600;
            box-shadow: 0 0 15px rgba(16, 185, 129, 0.2);
        }
        .btn-app:hover, .btn-app:active {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.4), rgba(6, 182, 212, 0.4));
            border-color: #34D399;
            box-shadow: 0 0 20px rgba(52, 211, 153, 0.4);
            transform: translateY(-1px);
        }

        .container {
            max-width: 1240px;
            margin: 24px auto;
            padding: 0 20px;
            width: 100%;
            flex: 1;
            position: relative;
            z-index: 10;
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: var(--card-glass);
            border: 1px solid var(--card-border);
            border-radius: var(--radius);
            padding: 18px 20px;
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
            background: linear-gradient(90deg, #6366F1, #A855F7, #EC4899);
            opacity: 0.7;
        }
        .stat-card:hover {
            border-color: var(--card-hover-border);
            box-shadow: 0 10px 30px rgba(129, 140, 248, 0.25);
            transform: translateY(-2px);
        }
        .stat-label {
            font-size: 13px;
            color: var(--text-sub);
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .stat-value {
            font-size: 24px;
            font-weight: 700;
            color: #FFFFFF;
            text-shadow: 0 0 12px rgba(255, 255, 255, 0.2);
            word-break: break-all;
        }
        
        /* Action Bar */
        .action-bar {
            background: var(--card-glass);
            border: 1px solid var(--card-border);
            border-radius: var(--radius);
            padding: 16px 20px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
            backdrop-filter: blur(16px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        .search-box {
            position: relative;
            flex: 1;
            min-width: 240px;
            max-width: 460px;
        }
        .search-box i {
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--accent-cyan);
        }
        .search-input {
            width: 100%;
            padding: 10px 14px 10px 40px;
            border-radius: 10px;
            background: rgba(3, 7, 18, 0.6);
            border: 1px solid var(--card-border);
            color: var(--text-main);
            font-size: 14px;
            outline: none;
            transition: all 0.2s;
        }
        .search-input:focus {
            border-color: var(--accent-cyan);
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.3);
            background: rgba(3, 7, 18, 0.85);
        }
        
        /* Cards Grid */
        .grid-cards {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(min(100%, 340px), 1fr));
            gap: 20px;
        }
        .pwd-card {
            background: var(--card-glass);
            border: 1px solid var(--card-border);
            border-radius: var(--radius);
            padding: 20px;
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        .pwd-card:hover {
            transform: translateY(-3px);
            border-color: rgba(56, 189, 248, 0.5);
            box-shadow: 0 12px 35px rgba(56, 189, 248, 0.2), 0 0 20px rgba(129, 140, 248, 0.15);
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
            gap: 8px;
        }
        .card-title {
            font-size: 17px;
            font-weight: 600;
            color: #FFFFFF;
            text-shadow: 0 0 10px rgba(255, 255, 255, 0.15);
            word-break: break-word;
        }
        .card-url {
            font-size: 12px;
            color: var(--accent-cyan);
            text-decoration: none;
            word-break: break-all;
            margin-top: 4px;
            display: inline-block;
            transition: 0.2s;
        }
        .card-url:hover {
            text-shadow: 0 0 8px rgba(56, 189, 248, 0.6);
        }
        .card-actions {
            display: flex;
            gap: 6px;
            flex-shrink: 0;
        }
        .icon-btn {
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 8px 10px;
            min-width: 36px;
            min-height: 36px;
            border-radius: 8px;
            cursor: pointer;
            color: var(--text-sub);
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }
        .icon-btn:hover, .icon-btn:active {
            background: rgba(129, 140, 248, 0.2);
            color: var(--accent-cyan);
            border-color: rgba(56, 189, 248, 0.4);
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.3);
        }
        .icon-btn.delete:hover, .icon-btn.delete:active {
            color: var(--accent-pink);
            background: rgba(244, 63, 94, 0.15);
            border-color: rgba(244, 63, 94, 0.4);
            box-shadow: 0 0 10px rgba(244, 63, 94, 0.3);
        }
        
        .pwd-field {
            background: rgba(3, 7, 18, 0.7);
            border: 1px solid rgba(129, 140, 248, 0.25);
            border-radius: 10px;
            padding: 10px 14px;
            margin: 10px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-family: "JetBrains Mono", "Fira Code", monospace;
            font-size: 14px;
            color: #38BDF8;
            box-shadow: inset 0 2px 6px rgba(0, 0, 0, 0.4);
            gap: 8px;
        }
        .pwd-text-val {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            flex: 1;
            user-select: all;
        }
        .account-row {
            font-size: 13px;
            color: var(--text-sub);
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .account-val {
            word-break: break-all;
        }
        .notes-row {
            font-size: 12px;
            color: #94A3B8;
            margin-top: 10px;
            border-top: 1px dashed rgba(255, 255, 255, 0.1);
            padding-top: 8px;
            word-break: break-word;
        }

        /* Mobile Drawer / Offcanvas */
        .drawer-overlay {
            position: fixed;
            inset: 0;
            background: rgba(3, 7, 18, 0.75);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            z-index: 90;
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.3s cubic-bezier(0.4, 0, 0.2, 1), visibility 0.3s;
        }
        .drawer-overlay.active {
            opacity: 1;
            visibility: visible;
        }
        .mobile-drawer {
            position: fixed;
            top: 0;
            right: -320px;
            width: min(85vw, 300px);
            height: 100%;
            height: 100vh;
            height: -webkit-fill-available;
            background: rgba(15, 23, 42, 0.95);
            border-left: 1px solid var(--card-border);
            box-shadow: -10px 0 30px rgba(0,0,0,0.7);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            z-index: 95;
            transition: right 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            flex-direction: column;
            padding: calc(env(safe-area-inset-top) + 16px) 16px calc(env(safe-area-inset-bottom) + 16px) 16px;
            overflow-y: auto;
            -webkit-overflow-scrolling: touch;
        }
        .mobile-drawer.active {
            right: 0;
        }
        .drawer-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 16px;
            margin-bottom: 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .drawer-menu-item {
            display: flex;
            align-items: center;
            gap: 12px;
            width: 100%;
            padding: 12px 14px;
            margin-bottom: 6px;
            border-radius: 10px;
            color: var(--text-main);
            background: transparent;
            border: 1px solid transparent;
            font-size: 14px;
            font-weight: 500;
            text-align: left;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s;
        }
        .drawer-menu-item:hover, .drawer-menu-item:active {
            background: rgba(129, 140, 248, 0.15);
            border-color: rgba(129, 140, 248, 0.3);
            color: var(--accent-cyan);
        }
        .drawer-menu-item i {
            width: 20px;
            text-align: center;
            font-size: 16px;
        }

        /* Cosmic Glass Modal */
        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(3, 7, 18, 0.8);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 100;
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            padding: 16px;
            overflow-y: auto;
            -webkit-overflow-scrolling: touch;
        }
        .modal-box {
            background: rgba(15, 23, 42, 0.95);
            width: 100%;
            max-width: 520px;
            border-radius: 20px;
            padding: 24px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.6), 0 0 30px rgba(99, 102, 241, 0.25);
            border: 1px solid rgba(255, 255, 255, 0.15);
            animation: scaleIn 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            max-height: 90vh;
            overflow-y: auto;
            -webkit-overflow-scrolling: touch;
        }
        @keyframes scaleIn {
            from { transform: scale(0.92); opacity: 0; }
            to { transform: scale(1); opacity: 1; }
        }
        .modal-title {
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 18px;
            color: #FFFFFF;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .form-group {
            margin-bottom: 16px;
        }
        .form-label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 6px;
            color: #CBD5E1;
        }
        .form-input {
            width: 100%;
            padding: 10px 14px;
            background: rgba(3, 7, 18, 0.7);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            font-size: 14px;
            color: #FFFFFF;
            outline: none;
            transition: all 0.2s;
        }
        .form-input:focus {
            border-color: var(--accent-cyan);
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.35);
            background: rgba(3, 7, 18, 0.9);
        }
        .modal-actions {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 22px;
            flex-wrap: wrap;
        }

        /* Login Screen */
        .login-wrapper {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 85vh;
            padding: 16px;
        }
        .login-card {
            background: rgba(15, 23, 42, 0.8);
            padding: 36px 30px;
            border-radius: 24px;
            width: 100%;
            max-width: 440px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5), 0 0 35px rgba(129, 140, 248, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        .login-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #6366F1, #A855F7, #EC4899, #38BDF8);
        }
        .login-logo {
            width: 64px;
            height: 64px;
            border-radius: 18px;
            background: linear-gradient(135deg, #6366F1, #A855F7, #EC4899);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 30px;
            margin: 0 auto 18px;
            box-shadow: 0 0 25px rgba(168, 85, 247, 0.6), inset 0 0 15px rgba(255, 255, 255, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.3);
            animation: pulseGlow 4s infinite alternate;
        }
        
        /* Cosmic Toast Notification */
        #toastContainer {
            position: fixed;
            bottom: 24px;
            right: 24px;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 10px;
            max-width: calc(100vw - 32px);
            pointer-events: none;
        }
        .cosmic-toast {
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid var(--accent-cyan);
            box-shadow: 0 0 20px rgba(56, 189, 248, 0.4);
            color: #FFFFFF;
            padding: 12px 18px;
            border-radius: 12px;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 10px;
            backdrop-filter: blur(10px);
            animation: toastIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            pointer-events: auto;
            word-break: break-word;
        }
        @keyframes toastIn {
            from { transform: translateY(20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        /* Responsive Breakpoints */
        @media (max-width: 992px) {
            .navbar {
                padding: 10px 16px;
            }
            .user-nav-desktop {
                display: none;
            }
            .user-nav-mobile {
                display: flex;
            }
            .brand-title .badge-secure {
                display: none;
            }
        }

        @media (max-width: 640px) {
            .navbar {
                padding: 8px 12px;
            }
            .logo-icon {
                width: 34px;
                height: 34px;
                min-width: 34px;
                font-size: 16px;
                border-radius: 10px;
            }
            .brand-title {
                font-size: 16px;
            }
            .container {
                padding: 0 12px;
                margin: 14px auto;
            }
            .stats-grid {
                grid-template-columns: 1fr;
                gap: 10px;
            }
            .stat-card {
                padding: 14px 16px;
            }
            .stat-value {
                font-size: 20px;
            }
            .action-bar {
                padding: 12px 14px;
                gap: 10px;
            }
            .search-box {
                max-width: 100%;
                min-width: 100%;
            }
            .btn-action-add {
                width: 100%;
            }
            .grid-cards {
                grid-template-columns: 1fr;
                gap: 14px;
            }
            .pwd-card {
                padding: 16px;
            }
            .modal-box {
                padding: 18px 14px;
                border-radius: 16px;
                max-height: 85vh;
            }
            .modal-actions button {
                flex: 1;
            }
            .login-card {
                padding: 28px 18px;
                border-radius: 20px;
            }
            #toastContainer {
                bottom: 16px;
                right: 16px;
                left: 16px;
                align-items: center;
            }
            .cosmic-toast {
                width: 100%;
                justify-content: center;
            }
            /* iOS Safari font zoom fix */
            .form-input, .search-input {
                font-size: 16px !important;
            }
        }
    </style>
</head>
<body>

<!-- Interactive Starfield Canvas -->
<canvas id="starfield"></canvas>
<div class="nebula-glow"></div>

<div id="toastContainer"></div>

<!-- Mobile Drawer Backdrop & Menu -->
<div id="drawerOverlay" class="drawer-overlay" onclick="closeDrawer()"></div>
<div id="mobileDrawer" class="mobile-drawer">
    <div class="drawer-header">
        <div style="display: flex; align-items: center; gap: 10px;">
            <div class="logo-icon" style="width: 32px; height: 32px; font-size: 16px;"><i class="fa-solid fa-user-astronaut"></i></div>
            <div style="font-size: 15px; font-weight: 700; color: #FFFFFF;" id="drawerUserLabel">管理员</div>
        </div>
        <button class="icon-btn" onclick="closeDrawer()" title="关闭菜单"><i class="fa-solid fa-xmark"></i></button>
    </div>
    
    <div style="margin-bottom: 12px;">
        <a href="/download/app.apk" class="btn btn-app" style="width: 100%; justify-content: center;" onclick="closeDrawer()">
            <i class="fa-brands fa-android"></i> 下载安卓客户端
        </a>
    </div>

    <button class="drawer-menu-item" onclick="closeDrawer(); showAddModal();">
        <i class="fa-solid fa-plus" style="color: var(--accent-cyan);"></i> 添加新记录
    </button>
    <button class="drawer-menu-item" onclick="closeDrawer(); showUpdateModal();">
        <i class="fa-solid fa-cloud-arrow-down" style="color: var(--accent-cyan);"></i> 检查系统更新
    </button>
    <button class="drawer-menu-item" onclick="closeDrawer(); showSecurityLogsModal();">
        <i class="fa-solid fa-shield-virus" style="color: var(--accent-pink);"></i> 安全审计日志
    </button>
    <button class="drawer-menu-item" onclick="closeDrawer(); showChangePwdModal();">
        <i class="fa-solid fa-lock" style="color: #FCD34D;"></i> 修改登录密码
    </button>
    <button class="drawer-menu-item" onclick="closeDrawer(); showRotateKeyModal();">
        <i class="fa-solid fa-key" style="color: #A855F7;"></i> 更换主私钥
    </button>
    <button class="drawer-menu-item" onclick="closeDrawer(); exportData();">
        <i class="fa-solid fa-download" style="color: #34D399;"></i> 导出备份数据
    </button>
    <button class="drawer-menu-item" onclick="closeDrawer(); showImportModal();">
        <i class="fa-solid fa-upload" style="color: #38BDF8;"></i> 导入恢复数据
    </button>

    <div style="margin-top: auto; padding-top: 16px; border-top: 1px solid rgba(255, 255, 255, 0.1);">
        <button class="drawer-menu-item" style="color: var(--accent-pink);" onclick="closeDrawer(); doLogout();">
            <i class="fa-solid fa-arrow-right-from-bracket"></i> 退出安全登录
        </button>
    </div>
</div>

<!-- Login Section -->
<div id="loginSection" class="container login-wrapper">
    <div class="login-card">
        <div class="login-logo"><i class="fa-solid fa-user-astronaut"></i></div>
        <h2 style="font-size: 22px; font-weight: 700; margin-bottom: 6px; color: #FFFFFF; text-shadow: 0 0 15px rgba(255,255,255,0.3);">星空密码管理器</h2>
        <p style="font-size: 13px; color: var(--text-sub); margin-bottom: 24px;">服务端全权安全加解密控制台 (Cosmic Vault)</p>
        <div class="form-group" style="text-align: left;">
            <label class="form-label"><i class="fa-solid fa-user-shield" style="color: var(--accent-cyan);"></i> 管理员用户名</label>
            <input type="text" id="loginUsername" class="form-input" value="jason" placeholder="请输入用户名" onkeyup="if(event.key==='Enter')doLogin()">
        </div>
        <div class="form-group" style="text-align: left;">
            <label class="form-label"><i class="fa-solid fa-key" style="color: var(--accent-cyan);"></i> 管理员密码</label>
            <input type="password" id="loginPassword" class="form-input" value="admin@1234" placeholder="请输入密码" onkeyup="if(event.key==='Enter')doLogin()">
        </div>
        <button class="btn btn-primary" style="width: 100%; justify-content: center; padding: 12px; margin-top: 8px;" onclick="doLogin()">
            <i class="fa-solid fa-meteor"></i> 启 动 星 空 控 制 台
        </button>
        <div style="margin-top: 18px;">
            <a href="/download/app.apk" class="btn btn-app" style="width: 100%; justify-content: center;">
                <i class="fa-brands fa-android"></i> 📱 下载卡通版安卓客户端 (APK)
            </a>
        </div>
        <div id="loginMsg" style="color: var(--accent-pink); font-size: 13px; margin-top: 14px; font-weight: 500;"></div>
    </div>
</div>

<!-- Main App Section -->
<div id="appSection" style="display: none; flex-direction: column; min-height: 100vh;">
    <nav class="navbar">
        <div class="logo-group">
            <div class="logo-icon"><i class="fa-solid fa-user-astronaut"></i></div>
            <div class="brand-title">
                <span>Cosmic Vault</span>
                <span class="badge-secure"><i class="fa-solid fa-shield-halved"></i> PBKDF2 + AES-256-GCM</span>
            </div>
        </div>
        
        <!-- Desktop Nav Items -->
        <div class="user-nav-desktop">
            <a href="/download/app.apk" class="btn btn-app" title="下载最新安卓版 APP">
                <i class="fa-brands fa-android"></i> 下载 APP
            </a>
            <span style="font-size: 13px; color: var(--text-sub); margin: 0 4px;" id="currentUserLabel"></span>
            <button class="btn btn-outline" style="border-color: rgba(56, 189, 248, 0.4); color: var(--accent-cyan);" onclick="showUpdateModal()"><i class="fa-solid fa-cloud-arrow-down"></i> 检查更新</button>
            <button class="btn btn-outline" style="border-color: rgba(244, 63, 94, 0.5); color: #FDA4AF;" onclick="showSecurityLogsModal()"><i class="fa-solid fa-shield-virus"></i> 安全审计日志</button>
            <button class="btn btn-outline" onclick="showChangePwdModal()"><i class="fa-solid fa-lock"></i> 修改密码</button>
            <button class="btn btn-outline" onclick="showRotateKeyModal()"><i class="fa-solid fa-key"></i> 更换私钥</button>
            <button class="btn btn-outline" onclick="exportData()"><i class="fa-solid fa-download"></i> 导出</button>
            <button class="btn btn-outline" onclick="showImportModal()"><i class="fa-solid fa-upload"></i> 导入</button>
            <button class="btn btn-outline" onclick="doLogout()" title="退出登录"><i class="fa-solid fa-arrow-right-from-bracket"></i></button>
        </div>

        <!-- Mobile Nav Hamburger -->
        <div class="user-nav-mobile">
            <a href="/download/app.apk" class="icon-btn" style="color: #34D399; border-color: rgba(16,185,129,0.3);" title="下载客户端">
                <i class="fa-brands fa-android"></i>
            </a>
            <button class="icon-btn" onclick="openDrawer()" title="打开菜单">
                <i class="fa-solid fa-bars" style="font-size: 17px; color: var(--text-main);"></i>
            </button>
        </div>
    </nav>

    <main class="container">
        <!-- Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label"><i class="fa-solid fa-database" style="color: var(--accent-cyan);"></i> 密码记录总数</div>
                <div class="stat-value" id="statTotalCount">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label"><i class="fa-solid fa-shield-virus" style="color: #A855F7;"></i> 服务端主加密密钥</div>
                <div class="stat-value" style="font-size: 14px; font-family: monospace; color: #38BDF8;" id="statKeyPreview">Loading...</div>
            </div>
            <div class="stat-card">
                <div class="stat-label"><i class="fa-solid fa-satellite" style="color: #34D399;"></i> 安全防护状态</div>
                <div class="stat-value" style="color: #34D399; font-size: 16px;"><i class="fa-solid fa-circle-check"></i> 星空全权加密中</div>
            </div>
        </div>

        <!-- Action Bar -->
        <div class="action-bar">
            <div class="search-box">
                <i class="fa-solid fa-magnifying-glass"></i>
                <input type="text" id="searchInput" class="search-input" placeholder="搜索网站名称、网址或账号..." oninput="renderPasswords()">
            </div>
            <button class="btn btn-primary btn-action-add" onclick="showAddModal()"><i class="fa-solid fa-plus"></i> 添加新密码记录</button>
        </div>

        <!-- Cards Container -->
        <div id="passwordGrid" class="grid-cards"></div>
    </main>
</div>

<!-- Modal: Add / Edit Password -->
<div id="pwdModal" class="modal-overlay">
    <div class="modal-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <h3 class="modal-title" id="modalTitle" style="margin-bottom: 0;"><i class="fa-solid fa-shield-cat" style="color: var(--accent-cyan);"></i> 添加密码记录</h3>
            <button class="icon-btn" onclick="closeModal('pwdModal')" title="关闭"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <input type="hidden" id="editId">
        <input type="hidden" id="mVersion">
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
                <label class="form-label" style="margin-bottom: 0;">密码 (由服务端 AES-256-GCM 加密) *</label>
                <a href="javascript:void(0)" style="font-size: 12px; color: var(--accent-cyan); text-decoration: none;" onclick="generateRandomPwd()"><i class="fa-solid fa-dice"></i> 生成强密码</a>
            </div>
            <input type="text" id="mPassword" class="form-input" style="font-family: monospace; color: #38BDF8;" placeholder="请输入或生成密码">
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

<!-- Modal: Change Password -->
<div id="changePwdModal" class="modal-overlay">
    <div class="modal-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <h3 class="modal-title" style="margin-bottom: 0;"><i class="fa-solid fa-key" style="color: var(--accent-cyan);"></i> 修改管理员登录密码</h3>
            <button class="icon-btn" onclick="closeModal('changePwdModal')" title="关闭"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <div class="form-group">
            <label class="form-label">当前原密码 *</label>
            <input type="password" id="cpOldPwd" class="form-input" placeholder="输入当前登录密码">
        </div>
        <div class="form-group">
            <label class="form-label">新登录密码 (至少6位) *</label>
            <input type="password" id="cpNewPwd" class="form-input" placeholder="输入新密码">
        </div>
        <div class="form-group">
            <label class="form-label">确认新密码 *</label>
            <input type="password" id="cpConfirmPwd" class="form-input" placeholder="请再次输入新密码">
        </div>
        <div class="modal-actions">
            <button class="btn btn-outline" onclick="closeModal('changePwdModal')">取消</button>
            <button class="btn btn-primary" onclick="doChangePassword()"><i class="fa-solid fa-check"></i> 确认修改密码</button>
        </div>
    </div>
</div>

<!-- Modal: Rotate Key -->
<div id="rotateModal" class="modal-overlay">
    <div class="modal-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <h3 class="modal-title" style="margin-bottom: 0;"><i class="fa-solid fa-arrows-rotate" style="color: #A855F7;"></i> 一键更换主加密私钥</h3>
            <button class="icon-btn" onclick="closeModal('rotateModal')" title="关闭"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <p style="font-size: 13px; color: var(--text-sub); margin-bottom: 16px; line-height: 1.5;">
            服务端将自动溯源历史密钥解密所有存量密码，并使用新私钥全量重新加密，保障绝对安全。
        </p>
        <div class="form-group">
            <label class="form-label">当前旧私钥 (留空使用服务端当前主私钥)</label>
            <input type="text" id="rotOldKey" class="form-input" style="font-family: monospace; color: #38BDF8;">
        </div>
        <div class="form-group">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <label class="form-label" style="margin-bottom: 0;">新加密主私钥 *</label>
                <a href="javascript:void(0)" style="font-size: 12px; color: var(--accent-cyan); text-decoration: none;" onclick="genNewRotateKey()"><i class="fa-solid fa-wand-magic-sparkles"></i> 随机生成</a>
            </div>
            <input type="text" id="rotNewKey" class="form-input" style="font-family: monospace; color: #38BDF8;" placeholder="输入新的加密主私钥">
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
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <h3 class="modal-title" style="margin-bottom: 0;"><i class="fa-solid fa-file-import" style="color: var(--accent-cyan);"></i> 导入私钥与密码记录</h3>
            <button class="icon-btn" onclick="closeModal('importModal')" title="关闭"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <div class="form-group">
            <label class="form-label">指定主私钥 (可选，将更新服务端私钥)</label>
            <input type="text" id="impKey" class="form-input" style="font-family: monospace; color: #38BDF8;" placeholder="输入指定私钥">
        </div>
        <div class="form-group">
            <label class="form-label">JSON 导入数据 *</label>
            <textarea id="impJson" class="form-input" rows="5" style="font-family: monospace; font-size: 12px; color: #38BDF8;" placeholder='{"private_key": "...", "records": [...] }'></textarea>
        </div>
        <div class="modal-actions">
            <button class="btn btn-outline" onclick="closeModal('importModal')">取消</button>
            <button class="btn btn-primary" onclick="doImport()"><i class="fa-solid fa-file-import"></i> 确认导入</button>
        </div>
    </div>
</div>

<!-- Modal: System Smooth Update -->
<div id="updateModal" class="modal-overlay">
    <div class="modal-box" style="max-width: 600px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
            <h3 class="modal-title" style="margin-bottom: 0;"><i class="fa-solid fa-cloud-arrow-down" style="color: var(--accent-cyan);"></i> 服务端在线平滑更新</h3>
            <button class="icon-btn" onclick="closeModal('updateModal')" title="关闭"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <p style="font-size: 13px; color: var(--text-sub); margin-bottom: 14px; line-height: 1.5;">
            从 GitHub Release 自动拉取最新服务端程序并平滑重启。系统在更新前<b>自动为数据库建立快照备份</b>，保障所有密码与私钥数据绝对零丢失。
        </p>

        <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 12px 14px; margin-bottom: 14px;">
            <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 13px;">
                <span style="color: var(--text-sub);">当前运行版本:</span>
                <span style="font-family: monospace; font-weight: 600; color: #FFFFFF;" id="updCurVer">v1.0.0</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 13px;">
                <span style="color: var(--text-sub);">GitHub 最新版本:</span>
                <span style="font-family: monospace; font-weight: 600; color: var(--accent-cyan);" id="updLatestVer">检测中...</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 6px 0; font-size: 13px;">
                <span style="color: var(--text-sub);">更新状态:</span>
                <span id="updStatusBadge" style="font-size: 12px; font-weight: 600; color: var(--accent-cyan);">正在查询 GitHub...</span>
            </div>
        </div>

        <div id="updNotesBox" style="display: none; background: rgba(0,0,0,0.2); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 10px 14px; max-height: 140px; overflow-y: auto; font-size: 12px; color: var(--text-sub); margin-bottom: 14px;">
            <div style="font-weight: 600; color: #FFFFFF; margin-bottom: 4px;">发布说明 / Release Notes:</div>
            <div id="updNotesContent" style="white-space: pre-wrap; line-height: 1.5;"></div>
        </div>

        <div id="updProgressBox" style="display: none; text-align: center; padding: 15px; background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 10px; margin-bottom: 14px;">
            <div style="color: var(--accent-cyan); font-size: 14px; font-weight: 600; margin-bottom: 6px;"><i class="fa-solid fa-spinner fa-spin"></i> <span id="updProgressText">正在执行平滑更新...</span></div>
            <div style="color: var(--text-sub); font-size: 12px;">数据库已备份，服务将在 5 秒后自动刷新...</div>
        </div>

        <div class="modal-actions">
            <button class="btn btn-outline" onclick="closeModal('updateModal')">取消</button>
            <button class="btn btn-primary" id="btnDoUpdate" onclick="doSmoothUpdate()"><i class="fa-solid fa-rocket"></i> 立即平滑更新 (保留数据)</button>
        </div>
    </div>
</div>

<!-- Modal: Security Audit Logs -->
<div id="securityLogsModal" class="modal-overlay">
    <div class="modal-box" style="max-width: 920px; width: 95%;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
            <h3 class="modal-title" style="margin-bottom: 0;"><i class="fa-solid fa-shield-virus" style="color: var(--accent-pink);"></i> 安全审计日志与风控看板</h3>
            <button class="icon-btn" onclick="closeModal('securityLogsModal')" title="关闭"><i class="fa-solid fa-xmark"></i></button>
        </div>

        <!-- 3 Stats Cards -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 14px;">
            <div style="background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.3); border-radius: 12px; padding: 10px 14px;">
                <div style="font-size: 11px; color: var(--text-sub);"><i class="fa-solid fa-triangle-exclamation" style="color: var(--accent-pink);"></i> 累计失败尝试</div>
                <div style="font-size: 20px; font-weight: 700; color: #FDA4AF; margin-top: 2px;" id="secStatFailed">0</div>
            </div>
            <div style="background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 12px; padding: 10px 14px;">
                <div style="font-size: 11px; color: var(--text-sub);"><i class="fa-solid fa-network-wired" style="color: var(--accent-cyan);"></i> 异常来源 IP 数</div>
                <div style="font-size: 20px; font-weight: 700; color: #38BDF8; margin-top: 2px;" id="secStatIps">0</div>
            </div>
            <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 12px; padding: 10px 14px;">
                <div style="font-size: 11px; color: var(--text-sub);"><i class="fa-solid fa-user-lock" style="color: #F59E0B;"></i> 当前封禁目标</div>
                <div style="font-size: 20px; font-weight: 700; color: #FCD34D; margin-top: 2px;" id="secStatLocked">0</div>
            </div>
        </div>

        <!-- Active Lockouts Banner -->
        <div id="activeLockoutSection" style="display: none; background: rgba(244, 63, 94, 0.15); border: 1px solid var(--accent-pink); border-radius: 12px; padding: 10px 12px; margin-bottom: 14px;">
            <div style="font-size: 12px; font-weight: 600; color: #FDA4AF; margin-bottom: 6px;"><i class="fa-solid fa-ban"></i> 当前正处于安全锁定中的目标：</div>
            <div id="activeLockoutList" style="display: flex; flex-wrap: wrap; gap: 6px;"></div>
        </div>

        <!-- Logs Table with Responsive Scroll Wrapper -->
        <div style="max-height: 360px; overflow-x: auto; overflow-y: auto; -webkit-overflow-scrolling: touch; border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; margin-bottom: 14px;">
            <table style="width: 100%; min-width: 600px; border-collapse: collapse; font-size: 12px; text-align: left;">
                <thead style="background: rgba(255,255,255,0.05); position: sticky; top: 0; backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);">
                    <tr>
                        <th style="padding: 9px 12px; color: var(--text-sub); white-space: nowrap;">时间 (UTC)</th>
                        <th style="padding: 9px 12px; color: var(--text-sub); white-space: nowrap;">来源 IP</th>
                        <th style="padding: 9px 12px; color: var(--text-sub); white-space: nowrap;">尝试用户名</th>
                        <th style="padding: 9px 12px; color: var(--text-sub); white-space: nowrap;">状态</th>
                        <th style="padding: 9px 12px; color: var(--text-sub); white-space: nowrap;">拦截原因</th>
                        <th style="padding: 9px 12px; color: var(--text-sub); white-space: nowrap;">客户端特征</th>
                    </tr>
                </thead>
                <tbody id="securityLogsTableBody">
                    <tr><td colspan="6" style="text-align: center; padding: 20px; color: var(--text-sub);">加载中...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="modal-actions" style="justify-content: space-between;">
            <button class="btn btn-outline" style="border-color: rgba(244,63,94,0.5); color: #FDA4AF;" onclick="clearSecurityLogs()"><i class="fa-solid fa-trash-can"></i> 清空日志</button>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <button class="btn btn-outline" onclick="loadSecurityLogs()"><i class="fa-solid fa-arrows-rotate"></i> 刷新</button>
                <button class="btn btn-primary" onclick="closeModal('securityLogsModal')">关闭</button>
            </div>
        </div>
    </div>
</div>

<script>
    // --- Starfield Particle Animation ---
    const canvas = document.getElementById("starfield");
    const ctx = canvas.getContext("2d");
    let stars = [];
    const isMobile = window.innerWidth < 768;
    const STAR_COUNT = isMobile ? 80 : 160;

    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    window.addEventListener("resize", () => {
        resizeCanvas();
        initStars();
    });

    function initStars() {
        stars = [];
        for (let i = 0; i < STAR_COUNT; i++) {
            stars.push({
                x: Math.random() * canvas.width,
                y: Math.random() * canvas.height,
                radius: Math.random() * 1.5 + 0.5,
                alpha: Math.random() * 0.8 + 0.2,
                dx: (Math.random() - 0.5) * 0.2,
                dy: (Math.random() - 0.5) * 0.2,
                twinkleSpeed: Math.random() * 0.02 + 0.005
            });
        }
    }

    function animateStars() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        stars.forEach(star => {
            star.alpha += star.twinkleSpeed;
            if (star.alpha > 1 || star.alpha < 0.2) star.twinkleSpeed = -star.twinkleSpeed;

            star.x += star.dx;
            star.y += star.dy;

            if (star.x < 0) star.x = canvas.width;
            if (star.x > canvas.width) star.x = 0;
            if (star.y < 0) star.y = canvas.height;
            if (star.y > canvas.height) star.y = 0;

            ctx.beginPath();
            ctx.arc(star.x, star.y, star.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(255, 255, 255, ${Math.max(0.1, Math.min(1, star.alpha))})`;
            ctx.shadowBlur = star.radius > 1.2 ? 6 : 0;
            ctx.shadowColor = "#38BDF8";
            ctx.fill();
        });
        requestAnimationFrame(animateStars);
    }

    resizeCanvas();
    initStars();
    animateStars();

    // --- Drawer Controls ---
    function openDrawer() {
        document.getElementById("drawerOverlay").classList.add("active");
        document.getElementById("mobileDrawer").classList.add("active");
    }
    function closeDrawer() {
        document.getElementById("drawerOverlay").classList.remove("active");
        document.getElementById("mobileDrawer").classList.remove("active");
    }

    // --- Toast Notifications ---
    function showToast(msg, icon = "fa-circle-check") {
        const container = document.getElementById("toastContainer");
        const toast = document.createElement("div");
        toast.className = "cosmic-toast";
        toast.innerHTML = `<i class="fa-solid ${icon}" style="color: var(--accent-cyan); font-size: 16px;"></i> <span>${msg}</span>`;
        container.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateY(20px)";
            toast.style.transition = "all 0.3s";
            setTimeout(() => toast.remove(), 300);
        }, 3200);
    }

    // --- State & API ---
    let authToken = localStorage.getItem("pwd_token") || "";
    let allRecords = [];
    let currentGlobalVersion = 0;
    let currentKey = "";
    
    // Inactivity Session Timeout Config (30 minutes default)
    const SESSION_TIMEOUT_MS = 30 * 60 * 1000;
    let inactivityTimer = null;

    function resetInactivityTimer() {
        if (!authToken) return;
        if (inactivityTimer) clearTimeout(inactivityTimer);
        inactivityTimer = setTimeout(() => {
            handleSessionTimeout();
        }, SESSION_TIMEOUT_MS);
    }

    function handleSessionTimeout() {
        if (!authToken) return;
        doLogout(true, "⏰ 由于您长时间未进行任何操作，登录会话已安全超时退出，请重新登录。");
    }

    // Attach user activity listeners across DOM
    ['mousedown', 'mousemove', 'keydown', 'touchstart', 'scroll', 'click'].forEach(evt => {
        window.addEventListener(evt, () => {
            resetInactivityTimer();
        }, { passive: true });
    });

    async function api(path, method = "GET", data = null) {
        const headers = { "Content-Type": "application/json" };
        if (authToken) headers["Authorization"] = "Bearer " + authToken;
        const res = await fetch(path, {
            method,
            headers,
            body: data ? JSON.stringify(data) : null
        });
        if (res.status === 401) {
            const errData = await res.json().catch(() => ({}));
            if (path !== "/api/auth/login" && path !== "/api/admin/login") {
                doLogout(true, "⏰ 登录会话已超时或失效，请重新登录。");
            }
            throw new Error(errData.error || "用户名或密码错误，请检查");
        }
        if (res.status === 409 || res.status === 400) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.error || "请求失败");
        }
        if (res.status === 429) {
            const errData = await res.json().catch(() => ({}));
            const msg = errData.error || "请求过于频繁或触发安全锁定，请稍后再试";
            showToast("🚫 " + msg, "fa-triangle-exclamation");
            throw new Error(msg);
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
            document.getElementById("drawerUserLabel").innerText = "用户: " + res.username;
            document.getElementById("loginMsg").innerText = "";
            showToast("登录成功，欢迎进入星空密码控制台！");
            resetInactivityTimer();
            initApp();
        } catch (e) {
            document.getElementById("loginMsg").innerText = "登录失败: " + e.message;
        }
    }

    async function doLogout(isTimeout = false, reason = "") {
        if (inactivityTimer) {
            clearTimeout(inactivityTimer);
            inactivityTimer = null;
        }
        const oldToken = authToken;
        authToken = "";
        localStorage.removeItem("pwd_token");
        document.getElementById("loginSection").style.display = "flex";
        document.getElementById("appSection").style.display = "none";
        closeDrawer();

        if (isTimeout) {
            const msg = reason || "⏰ 登录会话已超时，请重新登录。";
            document.getElementById("loginMsg").innerText = msg;
            showToast(msg, "fa-clock");
        } else {
            document.getElementById("loginMsg").innerText = "";
            showToast("已安全退出登录", "fa-right-from-bracket");
            if (oldToken) {
                try {
                    await fetch("/api/auth/logout", {
                        method: "POST",
                        headers: { "Content-Type": "application/json", "Authorization": "Bearer " + oldToken }
                    });
                } catch (ignored) {}
            }
        }
    }

    async function initApp() {
        try {
            const me = await api("/api/auth/me");
            document.getElementById("currentUserLabel").innerText = "用户: " + me.username;
            document.getElementById("drawerUserLabel").innerText = "用户: " + me.username;
            resetInactivityTimer();
        } catch (e) {
            doLogout(true, "⏰ 登录会话已过期，请重新登录。");
            return;
        }
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
            currentGlobalVersion = res.global_version !== undefined ? res.global_version : 0;
            document.getElementById("statTotalCount").innerText = allRecords.length;
            renderPasswords();
        } catch (e) {
            console.error("loadPasswords error:", e);
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
            grid.innerHTML = `<div style="grid-column: 1/-1; text-align: center; padding: 48px 16px; color: var(--text-sub);"><i class="fa-solid fa-satellite-dish" style="font-size: 32px; margin-bottom: 12px; color: rgba(255,255,255,0.2);"></i><div>暂无匹配的星空密码记录</div></div>`;
            return;
        }

        filtered.forEach(r => {
            const card = document.createElement("div");
            card.className = "pwd-card";
            card.innerHTML = `
                <div>
                    <div class="card-header">
                        <div style="flex: 1; min-width: 0;">
                            <div class="card-title">${escapeHtml(r.name)} <span style="font-size: 11px; background: rgba(56, 189, 248, 0.18); color: var(--accent-cyan); padding: 2px 6px; border-radius: 4px; font-weight: normal;">v${r.version !== undefined ? r.version : 0}</span></div>
                            ${r.url ? `<a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer" class="card-url"><i class="fa-solid fa-arrow-up-right-from-square"></i> ${escapeHtml(r.url)}</a>` : ""}
                        </div>
                        <div class="card-actions">
                            <button class="icon-btn" title="编辑" onclick="editPassword('${r.id}')"><i class="fa-solid fa-pen"></i></button>
                            <button class="icon-btn delete" title="删除" onclick="deletePassword('${r.id}', '${escapeHtml(r.name)}')"><i class="fa-solid fa-trash"></i></button>
                        </div>
                    </div>
                    <div class="account-row">
                        <span class="account-val">账号: <strong style="color: #FFFFFF;">${escapeHtml(r.username || "(无)")}</strong></span>
                        <a href="javascript:void(0)" onclick="copyText('${escapeJs(r.username)}', '账号')" style="color: var(--accent-cyan); text-decoration: none; font-size: 12px; flex-shrink: 0;"><i class="fa-regular fa-copy"></i> 复制</a>
                    </div>
                    <div class="pwd-field">
                        <span id="pwdText_${r.id}" class="pwd-text-val" style="letter-spacing: 2px;">••••••••</span>
                        <div style="display: flex; gap: 4px; flex-shrink: 0;">
                            <button class="icon-btn" id="toggleEye_${r.id}" title="显示明文密码" onclick="togglePasswordVisibility('${r.id}')"><i class="fa-solid fa-eye" id="eyeIcon_${r.id}"></i></button>
                            <button class="icon-btn" title="复制密码" onclick="copyText('${escapeJs(r.plain_password || "")}', '密码')"><i class="fa-solid fa-copy"></i></button>
                        </div>
                    </div>
                </div>
                ${r.notes ? `<div class="notes-row"><i class="fa-regular fa-note-sticky"></i> 备注: ${escapeHtml(r.notes)}</div>` : ""}
            `;
            grid.appendChild(card);
        });
    }

    function showAddModal() {
        document.getElementById("modalTitle").innerHTML = `<i class="fa-solid fa-shield-cat" style="color: var(--accent-cyan);"></i> 添加密码记录`;
        document.getElementById("editId").value = "";
        const mV = document.getElementById("mVersion"); if (mV) mV.value = "0";
        document.getElementById("mName").value = "";
        document.getElementById("mUrl").value = "";
        document.getElementById("mUsername").value = "";
        document.getElementById("mPassword").value = "";
        document.getElementById("mNotes").value = "";
        openModal("pwdModal");
    }

    function togglePasswordVisibility(id) {
        const item = allRecords.find(r => r.id === id);
        if (!item) return;
        const span = document.getElementById("pwdText_" + id);
        const icon = document.getElementById("eyeIcon_" + id);
        const btn = document.getElementById("toggleEye_" + id);
        if (!span || !icon) return;

        if (span.innerText === "••••••••") {
            span.innerText = item.plain_password || "(空密码)";
            span.style.letterSpacing = "normal";
            icon.className = "fa-solid fa-eye-slash";
            if (btn) btn.title = "隐藏明文密码";
        } else {
            span.innerText = "••••••••";
            span.style.letterSpacing = "2px";
            icon.className = "fa-solid fa-eye";
            if (btn) btn.title = "显示明文密码";
        }
    }

    function editPassword(id) {
        const item = allRecords.find(r => r.id === id);
        if (!item) return;
        document.getElementById("modalTitle").innerHTML = `<i class="fa-solid fa-pen-to-square" style="color: var(--accent-cyan);"></i> 编辑密码记录`;
        document.getElementById("editId").value = item.id;
        const mV = document.getElementById("mVersion"); if (mV) mV.value = item.version !== undefined ? item.version : 0;
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
            showToast("网站/应用名称和密码不能为空！", "fa-triangle-exclamation");
            return;
        }

        const dupeItem = allRecords.find(p => (p.name || '').trim().toLowerCase() === name.toLowerCase() && p.id !== id && !p.is_deleted);
        if (dupeItem) {
            showToast(`⚠️ 已存在相同名称「${escapeHtml(name)}」的记录，不允许重复添加！`, "fa-triangle-exclamation");
            return;
        }

        const payload = { name, url, username, password, notes, version: currentGlobalVersion };
        try {
            if (id) {
                payload.id = id;
                await api(`/api/passwords/${id}`, "PUT", payload);
                showToast("🎉 密码记录更新并已由服务端重新加密！");
            } else {
                await api("/api/passwords", "POST", payload);
                showToast("🎉 密码记录已由服务端 AES-256-GCM 安全加密！");
            }
            closeModal("pwdModal");
            await loadPasswords();
        } catch (e) {
            showToast("⚠️ 操作失败：" + e.message + "，已自动重新同步服务端数据与版本号！", "fa-triangle-exclamation");
            await loadPasswords();
        }
    }

    async function deletePassword(id, name) {
        if (confirm(`确定要删除「${name}」的记录吗？`)) {
            try {
                await api(`/api/passwords/${id}`, "DELETE");
                showToast(`已删除「${name}」的记录`);
                await loadPasswords();
            } catch (e) {
                showToast("⚠️ 删除失败：" + e.message + "，已自动重新同步服务端数据！", "fa-triangle-exclamation");
                await loadPasswords();
            }
        }
    }

    function showChangePwdModal() {
        document.getElementById("cpOldPwd").value = "";
        document.getElementById("cpNewPwd").value = "";
        document.getElementById("cpConfirmPwd").value = "";
        openModal("changePwdModal");
    }

    async function doChangePassword() {
        const old_password = document.getElementById("cpOldPwd").value;
        const new_password = document.getElementById("cpNewPwd").value;
        const confirm_password = document.getElementById("cpConfirmPwd").value;

        if (!old_password || !new_password) {
            showToast("原密码与新密码均不能为空", "fa-triangle-exclamation");
            return;
        }
        if (new_password.length < 6) {
            showToast("新密码长度不能少于 6 位", "fa-triangle-exclamation");
            return;
        }
        if (new_password !== confirm_password) {
            showToast("两次输入的新密码不一致", "fa-triangle-exclamation");
            return;
        }

        try {
            const res = await api("/api/auth/change-password", "POST", { old_password, new_password });
            if (res.token) {
                authToken = res.token;
                localStorage.setItem("pwd_token", authToken);
            }
            showToast("🎉 管理员密码修改成功！");
            closeModal("changePwdModal");
        } catch (e) {
            showToast(e.message || "密码修改失败", "fa-triangle-exclamation");
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
            showToast("新私钥不能为空", "fa-triangle-exclamation");
            return;
        }
        try {
            const res = await api("/api/admin/rotate-key", "POST", { old_key, new_key, reencrypt_records: true });
            showToast(`🎉 密钥更换成功！已自动重新加密 ${res.reencrypted_records_count} 条记录。`);
            closeModal("rotateModal");
            await loadKey();
            await loadPasswords();
        } catch (e) {
            showToast("⚠️ 密钥更换失败：" + e.message + "，已自动重新同步服务端数据！", "fa-triangle-exclamation");
            await loadPasswords();
        }
    }

    async function exportData() {
        const res = await api("/api/admin/export");
        const blob = new Blob([JSON.stringify(res, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `pwdmanager_export_${new Date().toISOString().slice(0,10)}.json`;
        a.click();
        showToast("私钥与密码数据已安全导出！");
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
            showToast("请输入要导入的 JSON 数据", "fa-triangle-exclamation");
            return;
        }
        let parsed;
        try {
            parsed = JSON.parse(raw);
        } catch (e) {
            showToast("JSON 格式不正确", "fa-triangle-exclamation");
            return;
        }

        const payload = {
            private_key: specKey || parsed.private_key,
            records: parsed.records || (Array.isArray(parsed) ? parsed : [])
        };

        try {
            const res = await api("/api/admin/import", "POST", payload);
            showToast(`🎉 导入成功！共导入 ${res.imported_records_count} 条记录。`);
            closeModal("importModal");
            await loadKey();
            await loadPasswords();
        } catch (e) {
            showToast("⚠️ 导入失败：" + e.message + "，已自动重新同步服务端数据！", "fa-triangle-exclamation");
            await loadPasswords();
        }
    }

    function generateRandomPwd() {
        const uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const lowers = "abcdefghijklmnopqrstuvwxyz";
        const digits = "0123456789";
        const specials = "!@#$%^&*()_+~-=";
        const all = uppers + lowers + digits + specials;

        let pwdArr = [];
        const randomValues = new Uint32Array(16);
        window.crypto.getRandomValues(randomValues);

        pwdArr.push(uppers[randomValues[0] % uppers.length]);
        pwdArr.push(lowers[randomValues[1] % lowers.length]);
        pwdArr.push(digits[randomValues[2] % digits.length]);
        pwdArr.push(specials[randomValues[3] % specials.length]);

        for (let i = 4; i < 16; i++) {
            pwdArr.push(all[randomValues[i] % all.length]);
        }

        for (let i = pwdArr.length - 1; i > 0; i--) {
            const j = randomValues[i] % (i + 1);
            const temp = pwdArr[i];
            pwdArr[i] = pwdArr[j];
            pwdArr[j] = temp;
        }

        const generated = pwdArr.join("");
        document.getElementById("mPassword").value = generated;
        showToast("🎲 已生成 16 位高强度随机密码！");
    }

    function genNewRotateKey() {
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~";
        let str = "Cosmic_";
        for (let i = 0; i < 24; i++) {
            str += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        document.getElementById("rotNewKey").value = str;
    }

    async function copyText(text, label = "内容") {
        if (!text) {
            showToast(`⚠️ ${label}为空，无法复制`, "fa-triangle-exclamation");
            return;
        }
        let copied = false;
        if (navigator.clipboard && window.isSecureContext) {
            try {
                await navigator.clipboard.writeText(text);
                copied = true;
            } catch (err) {
                console.warn("navigator.clipboard error, fallback to execCommand:", err);
            }
        }
        if (!copied) {
            try {
                const textArea = document.createElement("textarea");
                textArea.value = text;
                textArea.style.position = "fixed";
                textArea.style.top = "-9999px";
                textArea.style.left = "-9999px";
                textArea.style.opacity = "0";
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                copied = document.execCommand("copy");
                document.body.removeChild(textArea);
            } catch (err) {
                console.error("execCommand copy error:", err);
            }
        }
        if (copied) {
            showToast(`📋 ${label}已成功复制到剪贴板！`);
        } else {
            showToast(`❌ 复制失败，请手动选择复制`, "fa-triangle-exclamation");
        }
    }

    function openModal(id) { document.getElementById(id).style.display = "flex"; }
    function closeModal(id) { document.getElementById(id).style.display = "none"; }
    function escapeHtml(s) { return (s||'').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
    function escapeJs(s) { return (s || '').replace(/\\/g, "\\\\").replace(/'/g, "\\'"); }

    function showUpdateModal() {
        openModal("updateModal");
        checkUpdate();
    }

    async function checkUpdate() {
        document.getElementById("updCurVer").innerText = "v1.0.0";
        document.getElementById("updLatestVer").innerText = "正在拉取...";
        document.getElementById("updStatusBadge").innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> 正在查询 GitHub Release...`;
        document.getElementById("updNotesBox").style.display = "none";
        document.getElementById("updProgressBox").style.display = "none";
        document.getElementById("btnDoUpdate").disabled = false;

        try {
            const res = await api("/api/admin/check-update");
            document.getElementById("updCurVer").innerText = res.current_version || "v1.0.0";
            document.getElementById("updLatestVer").innerText = res.latest_version || res.current_version;

            if (res.has_update) {
                document.getElementById("updStatusBadge").innerHTML = `<span style="background: rgba(244,63,94,0.2); color: var(--accent-pink); padding: 2px 8px; border-radius: 4px;">🚀 发现新版本可用</span>`;
                if (res.release_notes) {
                    document.getElementById("updNotesBox").style.display = "block";
                    document.getElementById("updNotesContent").innerText = res.release_notes;
                }
            } else {
                document.getElementById("updStatusBadge").innerHTML = `<span style="background: rgba(16,185,129,0.2); color: #10B981; padding: 2px 8px; border-radius: 4px;"><i class="fa-solid fa-circle-check"></i> 当前已是最新版本</span>`;
                if (res.release_notes && res.release_notes.length > 5) {
                    document.getElementById("updNotesBox").style.display = "block";
                    document.getElementById("updNotesContent").innerText = res.release_notes;
                }
            }
        } catch (e) {
            document.getElementById("updStatusBadge").innerHTML = `<span style="color: var(--accent-pink);">查询失败: ${escapeHtml(e.message)}</span>`;
        }
    }

    async function doSmoothUpdate() {
        if (!confirm("确定要立即从 GitHub 拉取最新版本并平滑更新服务端吗？\n（系统将自动备份数据库，平滑重启约需 5 秒）")) return;

        const btn = document.getElementById("btnDoUpdate");
        btn.disabled = true;
        document.getElementById("updProgressBox").style.display = "block";
        document.getElementById("updProgressText").innerText = "正在从 GitHub 拉取更新并备份数据库...";

        try {
            const res = await api("/api/admin/update", "POST");
            showToast("🚀 " + (res.message || "更新指令已下发，正在平滑重启服务..."));
            document.getElementById("updProgressText").innerText = "平滑更新完成，正在重新加载页面...";

            let countdown = 5;
            const timer = setInterval(() => {
                countdown--;
                if (countdown <= 0) {
                    clearInterval(timer);
                    window.location.reload();
                } else {
                    document.getElementById("updProgressText").innerText = `服务重启中，将在 ${countdown} 秒后自动刷新页面...`;
                }
            }, 1000);
        } catch (e) {
            btn.disabled = false;
            document.getElementById("updProgressBox").style.display = "none";
            showToast(`❌ 更新失败: ${e.message}`, "fa-triangle-exclamation");
        }
    }

    function showSecurityLogsModal() {
        openModal('securityLogsModal');
        loadSecurityLogs();
    }

    async function loadSecurityLogs() {
        const tbody = document.getElementById("securityLogsTableBody");
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 20px; color: var(--text-sub);"><i class="fa-solid fa-spinner fa-spin"></i> 正在加载安全审计日志...</td></tr>`;

        try {
            const res = await api("/api/admin/security-logs?limit=100");
            document.getElementById("secStatFailed").innerText = res.total_failed_attempts || 0;
            document.getElementById("secStatIps").innerText = res.distinct_failed_ips || 0;

            const activeIps = (res.active_lockouts && res.active_lockouts.locked_ips) || [];
            const activeUsers = (res.active_lockouts && res.active_lockouts.locked_users) || [];
            document.getElementById("secStatLocked").innerText = activeIps.length + activeUsers.length;

            const lockoutSec = document.getElementById("activeLockoutSection");
            const lockoutList = document.getElementById("activeLockoutList");
            if (activeIps.length > 0 || activeUsers.length > 0) {
                lockoutSec.style.display = "block";
                let chipsHtml = "";
                activeIps.forEach(item => {
                    chipsHtml += `<div style="background: rgba(244,63,94,0.2); border: 1px solid var(--accent-pink); padding: 4px 10px; border-radius: 8px; font-size: 12px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                        <span>IP: <b style="font-family: monospace;">${escapeHtml(item.ip)}</b> (剩余 ${item.remaining_seconds}s)</span>
                        <button class="btn btn-outline" style="padding: 2px 8px; font-size: 11px; min-height: 24px; border-color: rgba(244,63,94,0.5); color: #FDA4AF;" onclick="unlockTarget('${escapeJs(item.ip)}', null)">解封</button>
                    </div>`;
                });
                activeUsers.forEach(item => {
                    chipsHtml += `<div style="background: rgba(245,158,11,0.2); border: 1px solid #F59E0B; padding: 4px 10px; border-radius: 8px; font-size: 12px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                        <span>账号: <b style="font-family: monospace;">${escapeHtml(item.username)}</b> (剩余 ${item.remaining_seconds}s)</span>
                        <button class="btn btn-outline" style="padding: 2px 8px; font-size: 11px; min-height: 24px; border-color: rgba(245,158,11,0.5); color: #FCD34D;" onclick="unlockTarget(null, '${escapeJs(item.username)}')">解锁</button>
                    </div>`;
                });
                lockoutList.innerHTML = chipsHtml;
            } else {
                lockoutSec.style.display = "none";
            }

            if (!res.logs || res.logs.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 25px; color: var(--text-sub);"><i class="fa-solid fa-circle-check" style="color: #10B981;"></i> 暂无异常登录或失败拦截记录，系统运行安全</td></tr>`;
                return;
            }

            let html = "";
            res.logs.forEach(l => {
                let statusBadge = "";
                if (l.status === "FAILED") {
                    statusBadge = `<span style="background: rgba(244,63,94,0.15); color: var(--accent-pink); padding: 2px 7px; border-radius: 6px; font-size: 11px; font-weight: 600; white-space: nowrap;">失败 (401)</span>`;
                } else if (l.status === "LOCKED_OUT") {
                    statusBadge = `<span style="background: rgba(239,68,68,0.25); color: #FF4D4D; border: 1px solid #EF4444; padding: 2px 7px; border-radius: 6px; font-size: 11px; font-weight: 600; white-space: nowrap;">封禁 (429)</span>`;
                } else {
                    statusBadge = `<span style="background: rgba(16,185,129,0.15); color: #10B981; padding: 2px 7px; border-radius: 6px; font-size: 11px; font-weight: 600; white-space: nowrap;">成功 (200)</span>`;
                }

                const timeStr = l.created_at ? l.created_at.replace("T", " ").substring(0, 19) : "";
                const uaShort = l.user_agent ? (l.user_agent.length > 30 ? escapeHtml(l.user_agent.substring(0, 30)) + "..." : escapeHtml(l.user_agent)) : "-";

                html += `<tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <td style="padding: 9px 12px; color: var(--text-sub); white-space: nowrap; font-family: monospace;">${timeStr}</td>
                    <td style="padding: 9px 12px; font-family: monospace; font-weight: 600; color: #FFFFFF; white-space: nowrap;">${escapeHtml(l.ip)}</td>
                    <td style="padding: 9px 12px; font-weight: 500; color: var(--accent-cyan); font-family: monospace; white-space: nowrap;">${escapeHtml(l.username_attempted)}</td>
                    <td style="padding: 9px 12px;">${statusBadge}</td>
                    <td style="padding: 9px 12px; color: var(--text-sub); white-space: nowrap;">${escapeHtml(l.failure_reason)}</td>
                    <td style="padding: 9px 12px; color: var(--text-sub); font-size: 11px;" title="${escapeHtml(l.user_agent)}">${uaShort}</td>
                </tr>`;
            });
            tbody.innerHTML = html;
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 20px; color: var(--accent-pink);">加载失败: ${escapeHtml(e.message)}</td></tr>`;
        }
    }

    async function unlockTarget(ip, username) {
        try {
            await api("/api/admin/security-logs/unlock", "POST", { ip: ip, username: username });
            showToast("🔓 已成功解除锁定！");
            loadSecurityLogs();
        } catch (e) {
            showToast(`❌ 解锁失败: ${e.message}`, "fa-triangle-exclamation");
        }
    }

    async function clearSecurityLogs() {
        if (!confirm("确定要清空所有历史安全审计与拦截日志吗？")) return;
        try {
            await api("/api/admin/security-logs", "DELETE");
            showToast("🧹 安全审计日志已清空！");
            loadSecurityLogs();
        } catch (e) {
            showToast(`❌ 清空失败: ${e.message}`, "fa-triangle-exclamation");
        }
    }

    if (authToken) {
        initApp();
    }
</script>
</body>
</html>"""

class RequestHandler(BaseHTTPRequestHandler):
    def _send_security_headers(self):
        origin = self.headers.get('Origin', '').strip()
        host = self.headers.get('Host', '').split(':')[0].strip()

        # Strict Origin Validation (Prevents Domain Suffix Spoofing and Unauthorized Cross-Origin Reading)
        if origin:
            try:
                parsed_origin = urlparse(origin)
                origin_host = parsed_origin.hostname or ""
                # Allow same host, localhost, loopback, or RFC 1918 private subnets
                if (origin_host == host or
                    origin_host in ["localhost", "127.0.0.1", "::1"] or
                    origin_host.startswith("192.168.") or
                    origin_host.startswith("10.") or
                    (origin_host.startswith("172.") and len(origin_host.split('.')) == 4 and 16 <= int(origin_host.split('.')[1]) <= 31)):
                    self.send_header('Access-Control-Allow-Origin', origin)
                    self.send_header('Vary', 'Origin')
            except Exception:
                pass

        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Auth-Token, X-Requested-With')
        self.send_header('Access-Control-Max-Age', '86400')
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
        raw_cl = self.headers.get('Content-Length', '').strip()
        if not raw_cl:
            return {}
        try:
            content_length = int(raw_cl)
        except ValueError:
            raise ValueError("Invalid Content-Length header")

        if content_length < 0:
            raise ValueError("Negative Content-Length not permitted")
        if content_length > MAX_REQUEST_BODY_SIZE:
            raise ValueError(f"Payload exceeds maximum allowed limit ({MAX_REQUEST_BODY_SIZE} bytes)")

        if content_length == 0:
            return {}
        body = self.rfile.read(content_length)
        if len(body) != content_length:
            raise ValueError("Request body truncated or incomplete")
        raw_str = body.decode('utf-8').strip()
        if not raw_str:
            return {}
        return json.loads(raw_str)

    def _get_client_ip(self):
        peer_ip = self.client_address[0]
        # Only trust X-Forwarded-For if peer is local reverse proxy and TRUST_PROXY is enabled
        if TRUST_PROXY and peer_ip in ["127.0.0.1", "::1"]:
            forwarded = self.headers.get('X-Forwarded-For')
            if forwarded:
                return forwarded.split(',')[0].strip()
        return peer_ip

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

        # Check for Updates API
        if path == '/api/admin/check-update':
            if not user or user.get('role') != 'admin':
                self._send_json(403, {"error": "Forbidden: Administrator privileges required"})
                return

            import urllib.request
            gh_url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
            gh_headers = {"User-Agent": "PwdManager-Server-Updater"}
            gh_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
            if gh_token:
                gh_headers["Authorization"] = f"token {gh_token}"

            try:
                gh_req = urllib.request.Request(gh_url, headers=gh_headers)
                with urllib.request.urlopen(gh_req, timeout=6) as gh_resp:
                    gh_data = json.loads(gh_resp.read().decode('utf-8'))
                    tag = gh_data.get("tag_name", "")
                    has_update = tag != SERVER_VERSION and tag != ""

                    tar_asset = next((a for a in gh_data.get("assets", []) if a.get("name") == "pwdmanager-server.tar.gz"), None)
                    download_url = tar_asset.get("browser_download_url") if tar_asset else f"https://github.com/{GITHUB_REPO}/releases/latest/download/pwdmanager-server.tar.gz"

                    self._send_json(200, {
                        "status": "ok",
                        "current_version": SERVER_VERSION,
                        "latest_version": tag,
                        "has_update": has_update,
                        "release_name": gh_data.get("name", tag),
                        "release_notes": gh_data.get("body", ""),
                        "published_at": gh_data.get("published_at", ""),
                        "download_url": download_url
                    })
            except Exception as ex:
                self._send_json(200, {
                    "status": "ok",
                    "current_version": SERVER_VERSION,
                    "latest_version": SERVER_VERSION,
                    "has_update": False,
                    "release_name": f"{SERVER_VERSION} (当前版本)",
                    "release_notes": "当前已是最新运行版本，或暂未连接至外网 Release。",
                    "published_at": get_iso_now(),
                    "download_url": f"https://github.com/{GITHUB_REPO}/releases/latest/download/pwdmanager-server.tar.gz",
                    "note": str(ex)
                })
            return

        # Security Audit Logs API
        if path == '/api/admin/security-logs':
            if not user or user.get('role') != 'admin':
                self._send_json(403, {"error": "Forbidden: Administrator privileges required"})
                return

            limit = int(query.get('limit', ['100'])[0])
            offset = int(query.get('offset', ['0'])[0])
            filter_ip = query.get('ip', [None])[0]
            filter_status = query.get('status', [None])[0]

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM security_audit_logs WHERE status != 'SUCCESS'")
            total_failed = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT ip) FROM security_audit_logs WHERE status != 'SUCCESS'")
            distinct_ips = cursor.fetchone()[0]

            sql = "SELECT id, ip, username_attempted, user_agent, status, failure_reason, created_at FROM security_audit_logs WHERE 1=1"
            params = []
            if filter_ip:
                sql += " AND ip = ?"
                params.append(filter_ip)
            if filter_status:
                sql += " AND status = ?"
                params.append(filter_status)

            sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([min(limit, 500), offset])

            cursor.execute(sql, params)
            logs = [dict(r) for r in cursor.fetchall()]
            conn.close()

            lockout_info = get_active_lockouts()

            self._send_json(200, {
                "status": "ok",
                "total_failed_attempts": total_failed,
                "distinct_failed_ips": distinct_ips,
                "active_lockouts": lockout_info,
                "logs": logs
            })
            return

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

            gv = get_global_version()
            self._send_json(200, {"count": len(rows), "global_version": gv, "records": rows})
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
        user_agent = self.headers.get('User-Agent', '')

        # 1. User & Admin Login (Dual-Dimension Anti-Brute-Force & Timing Attack Shield)
        if path == '/api/auth/login' or path == '/api/admin/login':
            username = (body.get('username') or body.get('user') or '').strip()
            password = str(body.get('password') or body.get('admin_secret') or '')

            # Check IP and Username rate limits
            is_locked, retry_after, lock_msg = check_rate_limit(client_ip, username)
            if is_locked:
                record_security_log(client_ip, username, user_agent, "LOCKED_OUT", lock_msg)
                self.send_response(429)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Retry-After', str(retry_after))
                self._send_security_headers()
                self.end_headers()
                resp = json.dumps({
                    "error": lock_msg,
                    "code": "ACCOUNT_OR_IP_LOCKED",
                    "retry_after": retry_after
                }, ensure_ascii=False).encode('utf-8')
                self.wfile.write(resp)
                return

            if not username or not password:
                self._send_json(400, {"error": "用户名和密码均不能为空"})
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
            else:
                # Timing Attack & Enumeration Shield:
                hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'pwdmanager_timing_shield_salt_2026', 100000)

            if authenticated:
                clear_failed_attempts(client_ip, username)
                record_security_log(client_ip, username, user_agent, "SUCCESS", "登录成功")
                token = secrets.token_hex(32)
                token_exp = get_iso_future_minutes(SESSION_TIMEOUT_MINUTES)
                cursor.execute("UPDATE users SET token = ?, token_expire_at = ?, updated_at = ? WHERE username = ?",
                               (token, token_exp, get_iso_now(), user_row['username']))
                conn.commit()
                conn.close()
                self._send_json(200, {
                    "status": "ok",
                    "username": user_row['username'],
                    "role": user_row['role'],
                    "token": token,
                    "expires_in": SESSION_TIMEOUT_MINUTES * 60,
                    "timeout_minutes": SESSION_TIMEOUT_MINUTES,
                    "expires_at": token_exp
                })
            else:
                conn.close()
                remaining = record_failed_attempt(client_ip, username)
                time.sleep(0.3)
                if remaining > 0:
                    err_msg = f"用户名或密码错误 (还剩 {remaining} 次尝试机会，连续失败将锁定 5 分钟)"
                else:
                    err_msg = f"用户名或密码错误，尝试次数已达上限，已触发 5 分钟安全锁定"
                record_security_log(client_ip, username, user_agent, "FAILED", err_msg)
                self._send_json(401, {
                    "error": err_msg,
                    "remaining_attempts": remaining,
                    "code": "INVALID_CREDENTIALS"
                })
            return

        # 1.4 Logout Endpoint (Invalidate Session Token on Server)
        if path == '/api/auth/logout' or path == '/api/admin/logout':
            auth_user = self._get_auth_user()
            if auth_user:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET token = '', token_expire_at = '', updated_at = ? WHERE username = ?",
                               (get_iso_now(), auth_user["username"]))
                conn.commit()
                conn.close()
                record_security_log(client_ip, auth_user["username"], user_agent, "LOGOUT", "主动安全退出登录")
            self._send_json(200, {"success": True, "message": "已安全退出登录"})
            return

        user = self._get_auth_user()
        if not user:
            self._send_json(401, {"error": "Unauthorized: Authentication required"})
            return

        # 1.5 Change Password Endpoint
        if path == '/api/auth/change-password' or path == '/api/admin/change-password':
            old_password = str(body.get('old_password') or '')
            new_password = str(body.get('new_password') or '')

            if not old_password or not new_password:
                self._send_json(400, {"error": "原密码与新密码均不能为空"})
                return

            if len(new_password) < 6:
                self._send_json(400, {"error": "新密码长度不能少于 6 位"})
                return

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (user["username"],))
            user_row = cursor.fetchone()

            if not user_row or not verify_password_pbkdf2(old_password, user_row['password_hash'], user_row['salt']):
                conn.close()
                self._send_json(400, {"error": "原密码验证失败，请检查后重试"})
                return

            new_phash, new_salt = hash_password_pbkdf2(new_password)
            new_token = secrets.token_hex(32)
            new_token_exp = get_iso_future(30)
            now = get_iso_now()

            cursor.execute("""
                UPDATE users SET password_hash = ?, salt = ?, token = ?, token_expire_at = ?, updated_at = ?
                WHERE username = ?
            """, (new_phash, new_salt, new_token, new_token_exp, now, user["username"]))
            conn.commit()
            conn.close()

            self._send_json(200, {
                "status": "ok",
                "message": "管理员密码修改成功",
                "username": user["username"],
                "token": new_token,
                "expires_at": new_token_exp
            })
            return

        # 2. Admin Rotate Key
        if path == '/api/admin/update':
            if not user or user.get('role') != 'admin':
                self._send_json(403, {"error": "Forbidden: Administrator privileges required"})
                return

            def run_smooth_update():
                time.sleep(0.5)
                # 1. Automatic database backup snapshot
                try:
                    backup_dir = os.path.join(BASE_DIR, "backups")
                    os.makedirs(backup_dir, exist_ok=True)
                    backup_file = os.path.join(backup_dir, f"passwords_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
                    if os.path.exists(DB_PATH):
                        src_conn = sqlite3.connect(DB_PATH)
                        dst_conn = sqlite3.connect(backup_file)
                        with dst_conn:
                            src_conn.backup(dst_conn)
                        dst_conn.close()
                        src_conn.close()
                        print(f"[+] Safe DB backup created: {backup_file}")
                except Exception as ex:
                    print(f"[-] Backup warning during update: {ex}")

                # 2. Check if update_server.sh exists locally
                update_sh = os.path.join(BASE_DIR, "update_server.sh")
                if os.path.exists(update_sh):
                    os.system(f"bash {update_sh} >> {os.path.join(BASE_DIR, 'update.log')} 2>&1 &")
                else:
                    # Fallback to in-place python download & restart
                    import urllib.request
                    try:
                        raw_url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/server/app.py"
                        req = urllib.request.Request(raw_url, headers={"User-Agent": "PwdManager-Server-Updater"})
                        with urllib.request.urlopen(req, timeout=10) as resp:
                            new_code = resp.read()
                            if len(new_code) > 1000 and b"ThreadedHTTPServer" in new_code:
                                with open(os.path.join(BASE_DIR, "app.py"), "wb") as f:
                                    f.write(new_code)
                        os.system("systemctl restart pwdmanager || (pkill -f 'python3.*app.py' && nohup python3 app.py 8000 &)")
                    except Exception as e:
                        print(f"[-] Smooth update execution error: {e}")

            threading.Thread(target=run_smooth_update, daemon=True).start()

            self._send_json(200, {
                "status": "updating",
                "message": "已成功下发平滑更新指令！数据库已建立安全快照备份，服务正在后台重启并无缝生效。"
            })
            return

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
            new_gv = get_global_version(conn)
            if reencrypted_count > 0:
                success, new_gv = increment_global_version(conn)
            conn.commit()
            conn.close()

            self._send_json(200, {
                "success": True,
                "message": "Key rotated successfully",
                "reencrypted_records_count": reencrypted_count,
                "global_version": new_gv,
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

                r_version = int(r.get('version', 0))
                cursor.execute("""
                    INSERT INTO password_entries (
                        id, name, url, username, encrypted_password, iv, salt, notes, created_at, updated_at, is_deleted, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        name=excluded.name, url=excluded.url, username=excluded.username,
                        encrypted_password=excluded.encrypted_password, iv=excluded.iv, salt=excluded.salt,
                        notes=excluded.notes, updated_at=excluded.updated_at, is_deleted=excluded.is_deleted,
                        version=excluded.version
                """, (r_id, r_name, r_url, r_username, r_enc_pwd, r_iv, r_salt, r_notes, r_created_at, r_updated_at, r_is_deleted, r_version))
                imported_count += 1

            new_gv = get_global_version(conn)
            if imported_count > 0:
                success, new_gv = increment_global_version(conn)
            conn.commit()
            conn.close()

            self._send_json(200, {
                "success": True,
                "imported_records_count": imported_count,
                "global_version": new_gv,
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

            # Disallow duplicate website/app name (Strictly enforced by name)
            cursor.execute("""
                SELECT id FROM password_entries
                WHERE LOWER(TRIM(name)) = LOWER(TRIM(?))
                  AND is_deleted = 0 AND id != ?
            """, (name, entry_id))
            if cursor.fetchone():
                conn.close()
                self._send_json(409, {
                    "error": f"已存在相同的网站/应用名称（{name}），不允许重复添加！只能基于已有记录进行修改。",
                    "code": "DUPLICATE_NAME"
                })
                return

            # Increment global version atomically
            success, new_gv = increment_global_version(conn)
            cursor.execute("""
                INSERT INTO password_entries (
                    id, name, url, username, encrypted_password, iv, salt, notes, created_at, updated_at, is_deleted, version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, url=excluded.url, username=excluded.username,
                    encrypted_password=excluded.encrypted_password, iv=excluded.iv, salt=excluded.salt,
                    notes=excluded.notes, updated_at=excluded.updated_at, is_deleted=excluded.is_deleted,
                    version=excluded.version
            """, (entry_id, name, url, username, encrypted_password, iv, salt, notes, created_at, updated_at, is_deleted, new_gv))
            conn.commit()

            cursor.execute("SELECT * FROM password_entries WHERE id = ?", (entry_id,))
            saved = dict(cursor.fetchone())
            saved["global_version"] = new_gv
            conn.close()

            self._send_json(201, saved)
            return

        # 5. Two-Way Sync (Global 64-bit Version Arbitration across arbitrary gaps)
        if path == '/api/passwords/sync':
            client_version = int(body.get('client_version', body.get('global_version', body.get('version', 0))))
            client_records = body.get('client_records', [])
            current_key = get_current_private_key()

            conn = get_db_connection()
            cursor = conn.cursor()
            server_version = get_global_version(conn)

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

                # 1. Match by ID first
                cursor.execute("SELECT * FROM password_entries WHERE id = ?", (r_id,))
                existing = cursor.fetchone()

                # 2. If not found by ID and active, match by name to avoid duplicate record creation
                if not existing and r_is_deleted == 0 and r_name.strip():
                    cursor.execute("SELECT * FROM password_entries WHERE LOWER(TRIM(name)) = LOWER(TRIM(?)) AND is_deleted = 0", (r_name,))
                    existing_by_name = cursor.fetchone()
                    if existing_by_name:
                        existing = existing_by_name
                        r_id = existing['id']

                if not existing:
                    # Brand new record on client -> always accept and insert
                    cursor.execute("""
                        INSERT INTO password_entries (
                            id, name, url, username, encrypted_password, iv, salt, notes, created_at, updated_at, is_deleted, version
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (r_id, r_name, r_url, r_username, r_enc_pwd, r_iv, r_salt, r_notes, r_created_at, r_updated_at, r_is_deleted, max(client_version, server_version)))
                    applied_count += 1
                else:
                    # Existing record present on both
                    target_id = existing['id']
                    if client_version > server_version:
                        cursor.execute("""
                            UPDATE password_entries SET
                                name = ?, url = ?, username = ?, encrypted_password = ?,
                                iv = ?, salt = ?, notes = ?, updated_at = ?, is_deleted = ?,
                                version = ?
                            WHERE id = ?
                        """, (r_name, r_url, r_username, r_enc_pwd, r_iv, r_salt, r_notes, r_updated_at, r_is_deleted, client_version, target_id))
                        applied_count += 1
                    elif client_version == server_version:
                        if r_updated_at > existing['updated_at']:
                            cursor.execute("""
                                UPDATE password_entries SET
                                    name = ?, url = ?, username = ?, encrypted_password = ?,
                                    iv = ?, salt = ?, notes = ?, updated_at = ?, is_deleted = ?
                                WHERE id = ?
                            """, (r_name, r_url, r_username, r_enc_pwd, r_iv, r_salt, r_notes, r_updated_at, r_is_deleted, target_id))
                            applied_count += 1

            if client_version > server_version:
                set_global_version(client_version, conn)
                server_version = client_version
            elif applied_count > 0:
                success, server_version = increment_global_version(conn)

            conn.commit()

            cursor.execute("SELECT * FROM password_entries")
            server_records = [dict(r) for r in cursor.fetchall()]
            conn.close()

            for r in server_records:
                r["plain_password"] = decrypt_password_server(r.get("encrypted_password", ""), r.get("iv", ""), r.get("salt", ""), current_key)

            self._send_json(200, {
                "server_time": get_iso_now(),
                "server_version": server_version,
                "global_version": server_version,
                "applied_from_client": applied_count,
                "server_records": server_records
            })
            return

        self._send_json(404, {"error": "Endpoint not found"})

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        if path == '/api/admin/security-logs':
            user = self._get_auth_user()
            if not user or user.get('role') != 'admin':
                self._send_json(403, {"error": "Forbidden: Administrator privileges required"})
                return
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM security_audit_logs")
            conn.commit()
            conn.close()
            self._send_json(200, {"success": True, "message": "安全审计日志已成功清空"})
            return

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

        # Disallow duplicate website/app name on edit
        cursor.execute("""
            SELECT id FROM password_entries
            WHERE LOWER(TRIM(name)) = LOWER(TRIM(?))
              AND is_deleted = 0 AND id != ?
        """, (name, entry_id))
        if cursor.fetchone():
            conn.close()
            self._send_json(409, {
                "error": f"已存在相同名称（{name}）的其他密码记录，不允许修改为重复名称！",
                "code": "DUPLICATE_NAME"
            })
            return

        if 'version' not in body:
            conn.close()
            self._send_json(400, {"error": "修改记录密码接口需要传入当前全局版本号 (version)", "code": "VERSION_REQUIRED"})
            return

        client_version = int(body.get('version', 0))
        server_global_version = get_global_version(conn)

        if client_version != server_global_version:
            conn.close()
            self._send_json(409, {
                "error": f"版本冲突：服务端当前全局版本为 v{server_global_version}，接口传入版本为 v{client_version}，拒绝修改！",
                "code": "VERSION_MISMATCH",
                "server_version": server_global_version,
                "global_version": server_global_version,
                "client_version": client_version
            })
            return

        # Atomic OCC: Increment global version
        success, new_gv = increment_global_version(conn, expected_ver=client_version)
        if not success:
            conn.rollback()
            conn.close()
            self._send_json(409, {
                "error": "并发修改冲突：服务端全局版本在更新过程中已变更，请刷新重试！",
                "code": "CONCURRENT_CONFLICT",
                "server_version": new_gv,
                "global_version": new_gv
            })
            return

        cursor.execute("""
            UPDATE password_entries SET
                name = ?, url = ?, username = ?, encrypted_password = ?,
                iv = ?, salt = ?, notes = ?, updated_at = ?, is_deleted = ?,
                version = ?
            WHERE id = ?
        """, (name, url, username, encrypted_password, iv, salt, notes, updated_at, is_deleted, new_gv, entry_id))

        conn.commit()

        cursor.execute("SELECT * FROM password_entries WHERE id = ?", (entry_id,))
        updated = dict(cursor.fetchone())
        updated["global_version"] = new_gv
        conn.close()

        self._send_json(200, updated)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        if path == '/api/admin/security-logs':
            user = self._get_auth_user()
            if not user or user.get('role') != 'admin':
                self._send_json(403, {"error": "Forbidden: Administrator privileges required"})
                return
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM security_audit_logs")
            conn.commit()
            conn.close()
            self._send_json(200, {"success": True, "message": "安全审计日志已成功清空"})
            return

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
        cursor.execute("SELECT id FROM password_entries WHERE id = ? AND is_deleted = 0", (entry_id,))
        if not cursor.fetchone():
            conn.close()
            self._send_json(404, {"error": "Record not found or already deleted"})
            return

        success, new_gv = increment_global_version(conn)
        cursor.execute("UPDATE password_entries SET is_deleted = 1, updated_at = ?, version = ? WHERE id = ?", (now, new_gv, entry_id))
        conn.commit()
        conn.close()

        self._send_json(200, {"success": True, "id": entry_id, "deleted_at": now, "global_version": new_gv})

def run_server(port=8000, host="0.0.0.0"):
    init_db()
    server_address = (host, port)
    httpd = ThreadedHTTPServer(server_address, RequestHandler)
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
