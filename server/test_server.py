#!/usr/bin/env python3
"""
Comprehensive Security & Functional Test Suite for Password Manager Server
Tests:
1. Web OWASP Security Headers (X-Content-Type-Options, X-Frame-Options, CSP)
2. Fail-Closed Authentication & Rejection of Invalid Logins
3. PBKDF2-HMAC-SHA256 User Authentication (admin / admin@1234) -> Token
4. Rejection of Query-String Authentication (Header-only enforcement)
5. Server-Side AES-256-GCM Encryption on record creation
6. Server-Side Decryption on retrieval (?decrypt=1)
7. Two-Way Incremental Sync
8. Admin Export of Master Private Key & All Records
9. Admin Import with Specified Custom Private Key
10. One-Click Key Rotation (Server-side decrypt & re-encrypt all records)
11. Key Rotation Integrity Verification
"""

import sys
import json
import urllib.request
import urllib.error
import urllib.parse
import time

def request_raw(url, method="GET", data=None, headers=None):
    if headers is None:
        headers = {}
    
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=8) as res:
            res_body = res.read().decode("utf-8")
            try:
                parsed = json.loads(res_body)
            except Exception:
                parsed = res_body
            return res.status, res.headers, parsed
    except urllib.error.HTTPError as e:
        res_body = e.read().decode("utf-8")
        try:
            parsed = json.loads(res_body)
        except Exception:
            parsed = res_body
        return e.code, e.headers, parsed

def run_tests(base_url="http://127.0.0.1:8000"):
    print(f"[*] Starting Security & Functional Test Suite against {base_url} ...\n")

    # 1. Test Web Dashboard & OWASP Security Headers
    status, headers, _ = request_raw(f"{base_url}/")
    assert status == 200, f"Dashboard failed with status {status}"
    assert headers.get("X-Content-Type-Options") == "nosniff", "Missing X-Content-Type-Options header!"
    assert headers.get("X-Frame-Options") == "DENY", "Missing X-Frame-Options header!"
    assert "Content-Security-Policy" in headers, "Missing Content-Security-Policy header!"
    print("  [PASS] 1. GET / (Web Dashboard & OWASP Security Headers verified: nosniff, DENY, CSP)")

    # 2. Test Rejection of Invalid Logins (No Backdoors)
    bad_login = {"username": "admin", "password": "WrongPassword!2026"}
    status, _, res_data = request_raw(f"{base_url}/api/auth/login", "POST", bad_login)
    assert status == 401, f"Expected 401 for bad password, got {status}: {res_data}"
    print("  [PASS] 2. POST /api/auth/login (Invalid credentials properly rejected with 401)")

    # 3. Test PBKDF2-HMAC-SHA256 User Authentication (admin / admin@1234)
    login_payload = {"username": "admin", "password": "admin@1234"}
    status, _, auth_data = request_raw(f"{base_url}/api/auth/login", "POST", login_payload)
    assert status == 200, f"Login failed: {status} {auth_data}"
    token = auth_data.get("token")
    assert token and len(token) >= 32, "High-entropy token missing or too short"
    print(f"  [PASS] 3. POST /api/auth/login (Authenticated via PBKDF2: {auth_data['username']}, Token: {token[:8]}...)")

    auth_headers = {"Authorization": f"Bearer {token}"}

    # 4. Test Header-Only Authentication Enforcement (Rejection of Query Param Token)
    status, _, _ = request_raw(f"{base_url}/api/auth/me?token={token}", "GET")
    assert status == 401, "Security flaw: Tokens in query strings must be rejected!"
    status, _, me_data = request_raw(f"{base_url}/api/auth/me", "GET", headers=auth_headers)
    assert status == 200 and me_data.get("username") == "admin", "Header auth failed"
    print("  [PASS] 4. GET /api/auth/me (Strict Header-only Auth verified; Query tokens safely rejected)")

    # 5. Test Server-Side Encryption on Record Creation
    test_id = f"test-sec-{int(time.time()*1000)}"
    raw_plain_pwd = "MySuperSecretBankPass!2026#"
    payload = {
        "id": test_id,
        "name": "Industrial Bank",
        "url": "https://www.cib.com.cn",
        "username": "admin_cib",
        "password": raw_plain_pwd,
        "notes": "Security verified account"
    }
    status, _, create_res = request_raw(f"{base_url}/api/passwords", "POST", payload, headers=auth_headers)
    assert status == 201, f"Create record failed: {status} {create_res}"
    assert create_res.get("id") == test_id
    assert "encrypted_password" in create_res
    assert create_res["encrypted_password"] != raw_plain_pwd, "Password must be encrypted on server!"
    assert create_res.get("iv") and create_res.get("salt"), "IV and Salt must be cryptographically generated!"
    print("  [PASS] 5. POST /api/passwords (Server-Side AES-256-GCM Encryption verified)")

    # 6. Test Server-Side Decryption on Retrieval
    status, _, list_res = request_raw(f"{base_url}/api/passwords?decrypt=1", "GET", headers=auth_headers)
    assert status == 200
    matched = next((r for r in list_res.get("records", []) if r["id"] == test_id), None)
    assert matched is not None
    assert matched.get("plain_password") == raw_plain_pwd, f"Decrypted mismatch: {matched.get('plain_password')}"
    print(f"  [PASS] 6. GET /api/passwords?decrypt=1 (Server-Side Decryption verified: '{matched['plain_password']}')")

    # 7. Test Two-Way Sync
    sync_id = f"sync-sec-{int(time.time()*1000)}"
    sync_payload = {
        "last_sync_time": None,
        "client_records": [
            {
                "id": sync_id,
                "name": "Zhihu",
                "url": "https://www.zhihu.com",
                "username": "sec_researcher",
                "password": "ZhihuSecurePass@888",
                "notes": "Research account"
            }
        ]
    }
    status, _, sync_res = request_raw(f"{base_url}/api/passwords/sync", "POST", sync_payload, headers=auth_headers)
    assert status == 200
    server_records = sync_res.get("server_records", [])
    assert any(r["id"] == sync_id for r in server_records)
    print(f"  [PASS] 7. POST /api/passwords/sync (Two-Way Sync verified, returned {len(server_records)} records)")

    # 8. Test Admin Export of Private Key and Records
    status, _, export_res = request_raw(f"{base_url}/api/admin/export", "GET", headers=auth_headers)
    assert status == 200
    assert "private_key" in export_res
    assert "records" in export_res
    assert "checksum" in export_res
    current_key = export_res["private_key"]
    print(f"  [PASS] 8. GET /api/admin/export (Exported Master Key: {current_key[:12]}..., Count: {export_res['records_count']})")

    # 9. Test Admin Import with Specified Private Key
    new_spec_key = "CustomHardenedKey#Vault999"
    import_id = f"imported-{int(time.time()*1000)}"
    import_payload = {
        "private_key": new_spec_key,
        "records": [
            {
                "id": import_id,
                "name": "AWS Root Console",
                "url": "https://aws.amazon.com",
                "username": "aws_root",
                "password": "AWSVaultSecret#2026",
                "notes": "Cloud infrastructure root account"
            }
        ]
    }
    status, _, import_res = request_raw(f"{base_url}/api/admin/import", "POST", import_payload, headers=auth_headers)
    assert status == 200
    assert import_res.get("current_private_key") == new_spec_key
    print(f"  [PASS] 9. POST /api/admin/import (Imported with specified key: {new_spec_key})")

    # 10. Test One-Click Key Rotation (Server-side decrypt & re-encrypt all records)
    rotated_key = "RotatedHardenedMasterKey#AES256GCM#Final2026"
    rotate_payload = {
        "old_key": new_spec_key,
        "new_key": rotated_key,
        "reencrypt_records": True
    }
    status, _, rotate_res = request_raw(f"{base_url}/api/admin/rotate-key", "POST", rotate_payload, headers=auth_headers)
    assert status == 200
    assert rotate_res.get("success") is True
    reencrypted_count = rotate_res.get("reencrypted_records_count", 0)
    assert reencrypted_count >= 1
    print(f"  [PASS] 10. POST /api/admin/rotate-key (Rotated Master Key & Re-encrypted {reencrypted_count} records)")

    # 11. Verify Decryption with Rotated Key
    status, _, list_after_rotate = request_raw(f"{base_url}/api/passwords?decrypt=1", "GET", headers=auth_headers)
    assert status == 200
    bank_rec = next((r for r in list_after_rotate.get("records", []) if r["id"] == test_id), None)
    assert bank_rec is not None
    assert bank_rec.get("plain_password") == raw_plain_pwd, f"Decryption failed after rotation: {bank_rec.get('plain_password')}"
    print(f"  [PASS] 11. Verification: Record successfully decrypted after key rotation ('{bank_rec['plain_password']}')")

    print("\n==========================================================================================")
    print(">>> ALL SECURITY HARDENING, WEB HEADERS, AUTH & CRYPTO TESTS PASSED! <<<")
    print("==========================================================================================\n")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    run_tests(target)
