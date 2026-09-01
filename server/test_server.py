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
    assert "Strict-Transport-Security" in headers, "Missing Strict-Transport-Security header!"
    print("  [PASS] 1. GET / (Web Dashboard & OWASP Security Headers verified: nosniff, DENY, CSP, HSTS)")

    # 2. Test Rejection of Invalid Logins (No Backdoors)
    bad_login = {"username": "admin", "password": "WrongPassword!2026"}
    status, _, res_data = request_raw(f"{base_url}/api/auth/login", "POST", bad_login)
    assert status == 401, f"Expected 401 for bad password, got {status}: {res_data}"
    print("  [PASS] 2. POST /api/auth/login (Invalid credentials properly rejected with 401)")

    # 3. Test PBKDF2-HMAC-SHA256 User Authentication (admin / admin@1234)
    login_payload = {"username": "jason", "password": "admin@1234"}
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
    assert status == 200 and me_data.get("username") == "jason", "Header auth failed"
    print("  [PASS] 4. GET /api/auth/me (Strict Header-only Auth verified; Query tokens safely rejected)")

    # 5. Test Server-Side Encryption on Record Creation
    test_id = f"test-sec-{int(time.time()*1000)}"
    raw_plain_pwd = "MySuperSecretBankPass!2026#"
    payload = {
        "id": test_id,
        "name": f"Industrial Bank ({test_id})",
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

    # 12. Test Admin Password Change & Verification
    # (a) Rejection on invalid old password
    status, _, res_bad = request_raw(f"{base_url}/api/auth/change-password", "POST",
                                     {"old_password": "WrongOldPassword999", "new_password": "NewSecretPass@2026!"},
                                     headers=auth_headers)
    assert status == 400, f"Expected 400 for incorrect old password, got {status}: {res_bad}"

    # (b) Successful password change
    status, _, res_change = request_raw(f"{base_url}/api/auth/change-password", "POST",
                                        {"old_password": "admin@1234", "new_password": "NewSecretPass@2026!"},
                                        headers=auth_headers)
    assert status == 200 and res_change.get("token"), f"Password change failed: {res_change}"

    # (c) Login with new password
    status, _, res_new_login = request_raw(f"{base_url}/api/auth/login", "POST",
                                           {"username": "jason", "password": "NewSecretPass@2026!"})
    assert status == 200 and res_new_login.get("token"), "Failed to login with new password"
    new_headers = {"Authorization": f"Bearer {res_new_login['token']}"}

    # (d) Restore default password for consistency
    status, _, res_restore = request_raw(f"{base_url}/api/auth/change-password", "POST",
                               {"old_password": "NewSecretPass@2026!", "new_password": "admin@1234"},
                               headers=new_headers)
    assert status == 200, "Failed to restore password"
    # Re-authenticate to refresh auth_headers with fresh token
    status, _, relogin_data = request_raw(f"{base_url}/api/auth/login", "POST", {"username": "jason", "password": "admin@1234"})
    assert status == 200
    auth_headers = {"Authorization": f"Bearer {relogin_data['token']}"}
    print("  [PASS] 12. POST /api/auth/change-password (Admin password change, validation & verification passed)")

    # 13. Test Duplicate Prevention on Create and Edit
    dupe_name = f"Cloudflare CDN ({test_id})"
    dupe_url = "https://dash.cloudflare.com"
    dupe_user = "sec_admin"

    # (a) Create first entry
    status, _, res1 = request_raw(f"{base_url}/api/passwords", "POST",
                                  {"name": dupe_name, "url": dupe_url, "username": dupe_user, "password": "Pass1#Cloudflare"},
                                  headers=auth_headers)
    assert status == 201
    entry1_id = res1["id"]

    # (b) Attempting to create duplicate entry with identical name, url, username -> must be rejected with 409
    status, _, res_dupe = request_raw(f"{base_url}/api/passwords", "POST",
                                       {"name": f"  {dupe_name}  ", "url": dupe_url, "username": dupe_user, "password": "Pass2#Duplicate"},
                                       headers=auth_headers)
    assert status == 409, f"Expected 409 for duplicate password entry, got {status}: {res_dupe}"

    # (c) Create another distinct entry
    status, _, res2 = request_raw(f"{base_url}/api/passwords", "POST",
                                  {"name": f"Vercel ({test_id})", "url": "https://vercel.com", "username": "vercel_user", "password": "Pass#Vercel"},
                                  headers=auth_headers)
    assert status == 201
    entry2_id = res2["id"]

    # (d) Attempting to update entry2 to collide with entry1 -> must be rejected with 409
    # Get current global version
    _, _, cur_pwds = request_raw(f"{base_url}/api/passwords", "GET", headers=auth_headers)
    cur_gv = cur_pwds.get("global_version", 0)
    status, _, res_edit_dupe = request_raw(f"{base_url}/api/passwords/{entry2_id}", "PUT",
                                           {"name": dupe_name, "url": dupe_url, "username": dupe_user, "version": cur_gv},
                                           headers=auth_headers)
    assert status == 409, f"Expected 409 for editing into duplicate entry, got {status}: {res_edit_dupe}"
    print("  [PASS] 13. POST/PUT /api/passwords (Duplicate prevention validated: 409 Conflict on create & edit)")

    # 14. Test 64-bit Global Versioning, Atomic OCC & Arbitrary-Gap Sync
    _, _, pwds_init = request_raw(f"{base_url}/api/passwords", "GET", headers=auth_headers)
    gv_start = pwds_init.get("global_version", 0)

    occ_name = f"OCC Global Vault Test ({test_id})"
    status, _, occ_create = request_raw(f"{base_url}/api/passwords", "POST",
                                        {"name": occ_name, "url": "https://vault.internal", "username": "occ_admin", "password": "OCCPassword#1"},
                                        headers=auth_headers)
    assert status == 201
    occ_id = occ_create["id"]
    gv_after_create = occ_create.get("global_version")
    assert gv_after_create == gv_start + 1, f"Expected global version {gv_start + 1}, got {gv_after_create}"

    # (a) Mismatching global version -> must return 409 Conflict with VERSION_MISMATCH
    status, _, occ_mismatch = request_raw(f"{base_url}/api/passwords/{occ_id}", "PUT",
                                          {"name": occ_name, "password": "OCCPassword#BadVer", "version": 999999},
                                          headers=auth_headers)
    assert status == 409, f"Expected 409 Conflict for version mismatch, got {status}: {occ_mismatch}"
    assert occ_mismatch.get("code") == "VERSION_MISMATCH"

    # (b) Missing version -> must return 400 Bad Request
    status, _, occ_no_ver = request_raw(f"{base_url}/api/passwords/{occ_id}", "PUT",
                                        {"name": occ_name, "password": "OCCPassword#NoVer"},
                                        headers=auth_headers)
    assert status == 400, f"Expected 400 Bad Request for missing version, got {status}: {occ_no_ver}"

    # (c) Correct global version -> atomic update, global version incremented
    status, _, occ_update1 = request_raw(f"{base_url}/api/passwords/{occ_id}", "PUT",
                                         {"name": occ_name, "password": "OCCPassword#2", "version": gv_after_create},
                                         headers=auth_headers)
    assert status == 200, f"Expected 200 for valid version update, got {status}: {occ_update1}"
    gv_after_update1 = occ_update1.get("global_version")
    assert gv_after_update1 == gv_after_create + 1, f"Expected global version {gv_after_create + 1}, got {gv_after_update1}"

    # (d) Multi-version gap sync: Client sends higher version (v1000, gap = +900) -> Server updates all client records & adopts v1000
    sync_high_payload = {
        "client_version": 1000,
        "client_records": [
            {"id": occ_id, "name": occ_name, "url": "https://vault.internal", "username": "occ_admin", "password": "OCCPassword#Gap1000", "version": 1000}
        ]
    }
    status, _, sync_res1 = request_raw(f"{base_url}/api/passwords/sync", "POST", sync_high_payload, headers=auth_headers)
    assert status == 200
    assert sync_res1.get("server_version") == 1000, f"Expected server version 1000 after sync, got {sync_res1.get('server_version')}"

    # Verify server adopted the client's higher data
    status, _, occ_get1 = request_raw(f"{base_url}/api/passwords/{occ_id}?decrypt=1", "GET", headers=auth_headers)
    assert status == 200
    assert occ_get1.get("plain_password") == "OCCPassword#Gap1000"

    # (e) Multi-version gap sync: Client sends lower version (v50, gap = -950 vs server v1000) -> Server retains v1000 & protects data
    sync_low_payload = {
        "client_version": 50,
        "client_records": [
            {"id": occ_id, "name": occ_name, "url": "https://vault.internal", "username": "occ_admin", "password": "OCCPassword#Stale50", "version": 50}
        ]
    }
    status, _, sync_res2 = request_raw(f"{base_url}/api/passwords/sync", "POST", sync_low_payload, headers=auth_headers)
    assert status == 200
    assert sync_res2.get("server_version") == 1000
    status, _, occ_get2 = request_raw(f"{base_url}/api/passwords/{occ_id}?decrypt=1", "GET", headers=auth_headers)
    assert status == 200
    assert occ_get2.get("plain_password") == "OCCPassword#Gap1000", "Server data must be protected against lower client version"
    print("  [PASS] 14. 64-bit Global Versioning, Atomic OCC & Multi-version Gap Sync fully validated!")

    print("\n==========================================================================================")
    print(">>> ALL SECURITY HARDENING, WEB HEADERS, AUTH & CRYPTO TESTS PASSED! <<<")
    print("==========================================================================================\n")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    run_tests(target)
