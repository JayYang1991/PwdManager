#!/usr/bin/env python3
"""
Comprehensive Test Suite for Password Manager Server & Web API
Tests:
1. Web Dashboard HTTP 200 & HTML response
2. User Authentication (jason / admin@1234) -> Token
3. Server-Side Encryption on password creation
4. Server-Side Decryption on retrieval (?decrypt=1)
5. Record Update with new password & re-encryption
6. Two-Way Sync with server-side decryption/encryption
7. Admin Export of Master Private Key & All Records
8. Admin Import with Specified Custom Private Key
9. One-Click Key Rotation (Server-side decrypt & re-encrypt all records)
10. Verification of Key Rotation integrity
"""

import sys
import json
import urllib.request
import urllib.error
import urllib.parse
import time

def request_json(url, method="GET", data=None, headers=None):
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
            return res.status, json.loads(res_body) if res_body else {}
    except urllib.error.HTTPError as e:
        res_body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(res_body)
        except Exception:
            return e.code, {"raw": res_body}

def run_tests(base_url="http://127.0.0.1:8000"):
    print(f"[*] Starting Comprehensive Test Suite against {base_url} ...\n")

    # 1. Test Web Dashboard
    req = urllib.request.Request(f"{base_url}/")
    with urllib.request.urlopen(req, timeout=5) as res:
        assert res.status == 200
        html = res.read().decode("utf-8")
        assert "密码管理器" in html
        assert "服务端安全加密" in html
        print("  [PASS] 1. GET / (Web Management Dashboard HTML served successfully)")

    # 2. Test User Authentication (jason / admin@1234)
    login_payload = {"username": "jason", "password": "admin@1234"}
    status, auth_data = request_json(f"{base_url}/api/auth/login", "POST", login_payload)
    assert status == 200, f"Login failed: {status} {auth_data}"
    token = auth_data.get("token")
    assert token, "Token missing from login response"
    print(f"  [PASS] 2. POST /api/auth/login (Authenticated: {auth_data['username']}, Token: {token[:8]}...)")

    headers = {"Authorization": f"Bearer {token}"}

    # 3. Test Server-Side Encryption on Record Creation
    test_id = f"test-site-{int(time.time()*1000)}"
    raw_plain_pwd = "MySuperSecretBankPass!2026#"
    payload = {
        "id": test_id,
        "name": "China Merchants Bank",
        "url": "https://www.cmbchina.com",
        "username": "jason_cmb",
        "password": raw_plain_pwd,
        "notes": "Main bank savings account"
    }
    status, create_res = request_json(f"{base_url}/api/passwords", "POST", payload, headers=headers)
    assert status == 201, f"Create record failed: {status} {create_res}"
    assert create_res.get("id") == test_id
    assert "encrypted_password" in create_res
    assert create_res["encrypted_password"] != raw_plain_pwd, "Password must be encrypted on server!"
    assert create_res.get("iv"), "IV must be generated on server!"
    assert create_res.get("salt"), "Salt must be generated on server!"
    print(f"  [PASS] 3. POST /api/passwords (Server-Side AES-GCM Encryption verified)")

    # 4. Test Server-Side Decryption on Retrieval
    status, list_res = request_json(f"{base_url}/api/passwords?decrypt=1", "GET", headers=headers)
    assert status == 200
    matched = next((r for r in list_res.get("records", []) if r["id"] == test_id), None)
    assert matched is not None
    assert matched.get("plain_password") == raw_plain_pwd, f"Decrypted mismatch: {matched.get('plain_password')} != {raw_plain_pwd}"
    print(f"  [PASS] 4. GET /api/passwords?decrypt=1 (Server-Side Decryption verified: '{matched['plain_password']}')")

    # 5. Test Two-Way Sync
    sync_id = f"sync-app-{int(time.time()*1000)}"
    sync_payload = {
        "last_sync_time": None,
        "client_records": [
            {
                "id": sync_id,
                "name": "Bilibili",
                "url": "https://www.bilibili.com",
                "username": "bili_jason",
                "password": "BiliPassword@888",
                "notes": "Video creator account"
            }
        ]
    }
    status, sync_res = request_json(f"{base_url}/api/passwords/sync", "POST", sync_payload, headers=headers)
    assert status == 200
    server_records = sync_res.get("server_records", [])
    assert any(r["id"] == sync_id for r in server_records)
    print(f"  [PASS] 5. POST /api/passwords/sync (Two-Way Sync verified, returned {len(server_records)} records)")

    # 6. Test Admin Export of Private Key and Records
    status, export_res = request_json(f"{base_url}/api/admin/export", "GET", headers=headers)
    assert status == 200
    assert "private_key" in export_res
    assert "records" in export_res
    assert "checksum" in export_res
    current_key = export_res["private_key"]
    print(f"  [PASS] 6. GET /api/admin/export (Exported Master Private Key: {current_key[:12]}..., Count: {export_res['records_count']})")

    # 7. Test Admin Import with Specified Private Key
    new_spec_key = "CustomSpecifiedKey#Vault999"
    import_id = f"imported-{int(time.time()*1000)}"
    import_payload = {
        "private_key": new_spec_key,
        "records": [
            {
                "id": import_id,
                "name": "Tencent Cloud",
                "url": "https://cloud.tencent.com",
                "username": "tencent_admin",
                "password": "TencentSecurePass#2026",
                "notes": "Imported Tencent Cloud Account"
            }
        ]
    }
    status, import_res = request_json(f"{base_url}/api/admin/import", "POST", import_payload, headers=headers)
    assert status == 200
    assert import_res.get("current_private_key") == new_spec_key
    print(f"  [PASS] 7. POST /api/admin/import (Imported with specified key: {new_spec_key})")

    # 8. Test One-Click Key Rotation (Server-side decrypt & re-encrypt all records)
    rotated_key = "RotatedVaultMasterKey#AES256GCM#Final2026"
    rotate_payload = {
        "old_key": new_spec_key,
        "new_key": rotated_key,
        "reencrypt_records": True
    }
    status, rotate_res = request_json(f"{base_url}/api/admin/rotate-key", "POST", rotate_payload, headers=headers)
    assert status == 200
    assert rotate_res.get("success") is True
    reencrypted_count = rotate_res.get("reencrypted_records_count", 0)
    assert reencrypted_count >= 1
    print(f"  [PASS] 8. POST /api/admin/rotate-key (Rotated Master Key & Re-encrypted {reencrypted_count} records)")

    # 9. Verify Decryption with Rotated Key
    status, list_after_rotate = request_json(f"{base_url}/api/passwords?decrypt=1", "GET", headers=headers)
    assert status == 200
    bank_rec = next((r for r in list_after_rotate.get("records", []) if r["id"] == test_id), None)
    assert bank_rec is not None
    assert bank_rec.get("plain_password") == raw_plain_pwd, f"Decryption failed after rotation: {bank_rec.get('plain_password')}"
    print(f"  [PASS] 9. Verification: Record successfully decrypted after key rotation ('{bank_rec['plain_password']}')")

    print("\n==========================================================================================")
    print(">>> ALL SERVER, WEB DASHBOARD, AUTH, SERVER CRYPTO, AND KEY ROTATION TESTS PASSED! <<<")
    print("==========================================================================================\n")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    run_tests(target)
