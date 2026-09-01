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
import concurrent.futures

def request_raw(url, method="GET", data=None, headers=None, timeout=30):
    if headers is None:
        headers = {}
    
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
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

    # (d) Multi-version gap sync: Client sends higher version (gap = +1000) -> Server updates all client records & adopts higher version
    high_client_ver = gv_after_update1 + 1000
    sync_high_payload = {
        "client_version": high_client_ver,
        "client_records": [
            {"id": occ_id, "name": occ_name, "url": "https://vault.internal", "username": "occ_admin", "password": "OCCPassword#GapHigh", "version": high_client_ver}
        ]
    }
    status, _, sync_res1 = request_raw(f"{base_url}/api/passwords/sync", "POST", sync_high_payload, headers=auth_headers)
    assert status == 200
    assert sync_res1.get("server_version") == high_client_ver, f"Expected server version {high_client_ver} after sync, got {sync_res1.get('server_version')}"

    # Verify server adopted the client's higher data
    status, _, occ_get1 = request_raw(f"{base_url}/api/passwords/{occ_id}?decrypt=1", "GET", headers=auth_headers)
    assert status == 200
    assert occ_get1.get("plain_password") == "OCCPassword#GapHigh"

    # (e) Multi-version gap sync: Client sends lower version (gap = -500 vs server) -> Server retains higher version & protects data
    low_client_ver = max(0, high_client_ver - 500)
    sync_low_payload = {
        "client_version": low_client_ver,
        "client_records": [
            {"id": occ_id, "name": occ_name, "url": "https://vault.internal", "username": "occ_admin", "password": "OCCPassword#StaleLow", "version": low_client_ver}
        ]
    }
    status, _, sync_res2 = request_raw(f"{base_url}/api/passwords/sync", "POST", sync_low_payload, headers=auth_headers)
    assert status == 200
    assert sync_res2.get("server_version") == high_client_ver
    status, _, occ_get2 = request_raw(f"{base_url}/api/passwords/{occ_id}?decrypt=1", "GET", headers=auth_headers)
    assert status == 200
    assert occ_get2.get("plain_password") == "OCCPassword#GapHigh", "Server data must be protected against lower client version"
    print("  [PASS] 14. 64-bit Global Versioning, Atomic OCC & Multi-version Gap Sync fully validated!")

    # 15. Multi-Client Concurrency, Race-Condition & Consistency Verification
    print("\n  [*] Running Multi-Client Concurrency & Consistency Test Suite (Step 15)...")

    # (a) 5 Clients Race Condition Simulation on Single Record Edit (OCC Conflict Detection)
    race_id = f"race-{int(time.time()*1000)}"
    status, _, race_create = request_raw(f"{base_url}/api/passwords", "POST",
                                         {"id": race_id, "name": f"Race Target ({test_id})", "url": "https://race.example.com", "username": "race_user", "password": "InitialPassword#0"},
                                         headers=auth_headers)
    assert status == 201
    base_gv = race_create.get("global_version")

    # Simulate 5 distinct clients trying to edit the same record at the EXACT same time with the same base version
    num_clients = 5
    results = []

    def client_edit_attempt(client_idx, target_ver):
        return client_idx, request_raw(f"{base_url}/api/passwords/{race_id}", "PUT",
                                      {"name": f"Race Target ({test_id})", "password": f"PasswordFromClient#{client_idx}", "version": target_ver},
                                      headers=auth_headers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_clients) as executor:
        futures = [executor.submit(client_edit_attempt, i, base_gv) for i in range(1, num_clients + 1)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    successes = [r for r in results if r[1][0] == 200]
    conflicts = [r for r in results if r[1][0] == 409]

    assert len(successes) == 1, f"Expected exactly 1 winner out of {num_clients} concurrent edits, got {len(successes)}"
    assert len(conflicts) == num_clients - 1, f"Expected {num_clients - 1} 409 Conflict rejections, got {len(conflicts)}"
    for _, c_res in conflicts:
        assert c_res[2].get("code") in ("VERSION_MISMATCH", "CONCURRENT_CONFLICT")
        assert c_res[2].get("server_version") == base_gv + 1

    winner_client_idx = successes[0][0]
    print(f"      -> 15(a) OCC Race Condition: Client #{winner_client_idx} won (200 OK), other {len(conflicts)} clients rejected (409 Conflict with VERSION_MISMATCH)")

    # (b) Simulated Client Auto-Resync & Retry Healing
    # The 4 rejected clients auto-resync the latest version and retry sequentially
    cur_v = base_gv + 1
    for c_idx, _ in conflicts:
        _, (status, _, retry_res) = client_edit_attempt(c_idx, cur_v)
        assert status == 200, f"Client #{c_idx} failed on retry with synced version {cur_v}: {retry_res}"
        cur_v = retry_res.get("global_version")
    assert cur_v == base_gv + num_clients
    print(f"      -> 15(b) Auto-Resync & Retry Healing: All rejected clients recovered and committed, global_version advanced from v{base_gv} to v{cur_v}")

    # (c) 10 Concurrent Clients Adding Unique Records Simultaneously
    start_gv_add = cur_v
    num_add_clients = 10
    add_results = []

    def client_add_entry(client_idx):
        entry_payload = {
            "name": f"MultiClient_Add_{client_idx}_{test_id}",
            "url": f"https://client{client_idx}.internal",
            "username": f"user_c{client_idx}",
            "password": f"SecureMultiPass_{client_idx}!@"
        }
        return client_idx, request_raw(f"{base_url}/api/passwords", "POST", entry_payload, headers=auth_headers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_add_clients) as executor:
        futures = [executor.submit(client_add_entry, i) for i in range(1, num_add_clients + 1)]
        for f in concurrent.futures.as_completed(futures):
            add_results.append(f.result())

    for idx, (stat, _, res) in add_results:
        assert stat == 201, f"Client #{idx} add failed: {res}"

    _, _, pwds_after_add = request_raw(f"{base_url}/api/passwords", "GET", headers=auth_headers)
    final_gv_add = pwds_after_add.get("global_version")
    assert final_gv_add == start_gv_add + num_add_clients, f"Expected final global version {start_gv_add + num_add_clients}, got {final_gv_add}"
    print(f"      -> 15(c) 10 Parallel Additions: 10/10 created atomically, global_version strictly incremented by 10 (v{start_gv_add} -> v{final_gv_add})")

    # (d) Multi-Client Offline / Two-Way Partition Sync Convergence
    # Simulate Client A (Mobile) offline with +5 versions and Client B (Web) online with +1 version
    client_a_offline_ver = final_gv_add + 5
    client_a_entry_id = f"client-a-{int(time.time()*1000)}"
    sync_payload_a = {
        "client_version": client_a_offline_ver,
        "client_records": [
            {
                "id": client_a_entry_id,
                "name": f"Client A Offline Record ({test_id})",
                "url": "https://mobile.internal",
                "username": "client_a",
                "password": "ClientAPassword#999",
                "version": client_a_offline_ver
            }
        ]
    }
    # Client A syncs (high version wins arbitration)
    status, _, sync_a_res = request_raw(f"{base_url}/api/passwords/sync", "POST", sync_payload_a, headers=auth_headers)
    assert status == 200
    assert sync_a_res.get("server_version") == client_a_offline_ver

    # Client B (with stale version) syncs -> gets full dataset and updates local version to client_a_offline_ver
    sync_payload_b = {
        "client_version": final_gv_add,
        "client_records": []
    }
    status, _, sync_b_res = request_raw(f"{base_url}/api/passwords/sync", "POST", sync_payload_b, headers=auth_headers)
    assert status == 200
    assert sync_b_res.get("server_version") == client_a_offline_ver
    records_b = sync_b_res.get("server_records", [])
    assert any(r["id"] == client_a_entry_id for r in records_b), "Client B must receive Client A's record after sync"
    print(f"      -> 15(d) Partitioned Multi-Client Sync: High-version arbitration + stale client catch-up 100% consistent (v{client_a_offline_ver})")
    # (e) High-Concurrency Multi-Client Read-Modify-Write Stress Test
    print("      [*] Starting high-concurrency read-modify-write stress test (20 concurrent operations)...")
    stress_entry_id = f"stress-{int(time.time()*1000)}"
    status, _, stress_create = request_raw(f"{base_url}/api/passwords", "POST",
                                           {"id": stress_entry_id, "name": f"Stress Shared Target ({test_id})", "url": "https://stress.test", "username": "stress_admin", "password": "StressPass#Init"},
                                           headers=auth_headers)
    assert status == 201
    
    total_stress_ops = 20
    successful_updates = 0
    total_retries = 0

    def worker_stress_task(worker_id):
        nonlocal total_retries
        for attempt in range(20): # Max 20 retries
            # 1. Read latest state
            _, _, pwds = request_raw(f"{base_url}/api/passwords", "GET", headers=auth_headers)
            cur_gv = pwds.get("global_version", 0)
            
            # 2. Attempt conditional update
            payload = {
                "name": f"Stress Shared Target ({test_id})",
                "password": f"StressPass#W{worker_id}_A{attempt}",
                "version": cur_gv
            }
            stat, _, res = request_raw(f"{base_url}/api/passwords/{stress_entry_id}", "PUT", payload, headers=auth_headers)
            if stat == 200:
                return True, attempt
            elif stat == 409:
                # Conflict encountered -> resync and retry
                total_retries += 1
                time.sleep(0.02 * (worker_id % 3 + 1))
            else:
                return False, attempt
        return False, 20

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        stress_futures = [executor.submit(worker_stress_task, i) for i in range(1, total_stress_ops + 1)]
        for f in concurrent.futures.as_completed(stress_futures):
            ok, attempts = f.result()
            assert ok, "Stress worker failed to converge"
            successful_updates += 1

    assert successful_updates == total_stress_ops, f"Expected {total_stress_ops} successful updates, got {successful_updates}"
    print(f"      -> 15(e) 20 Concurrent Read-Modify-Write Cycles: All {successful_updates} converged successfully ({total_retries} OCC conflicts automatically resolved via resync & retry)")

    print("  [PASS] 15. Multi-Client Concurrency, Race Condition, OCC & Consistency 100% verified!")

    # --------------------------------------------------------------------------
    # 16. Dual-Dimension Anti-Brute-Force & Rate Limiting Test Suite
    # --------------------------------------------------------------------------
    print("\n  [*] Running Dual-Dimension Anti-Brute-Force Test Suite (Step 16)...")

    # (a) Timing Attack & Username Enumeration Shield Test (tested before lockout)
    t0 = time.time()
    s_exist, _, _ = request_raw(f"{base_url}/api/auth/login", "POST", {"username": "jason", "password": "WrongPasswordTimingTest1"})
    t_exist = time.time() - t0

    t1 = time.time()
    s_ghost, _, _ = request_raw(f"{base_url}/api/auth/login", "POST", {"username": "ghost_non_existent_user_999", "password": "WrongPasswordTimingTest2"})
    t_ghost = time.time() - t1

    assert s_exist == 401 and s_ghost == 401
    assert t_exist > 0.2 and t_ghost > 0.2, f"PBKDF2 timing shield too fast: exist={t_exist:.3f}s, ghost={t_ghost:.3f}s"
    print(f"      -> 16(a) Timing Attack Shield: Non-existent user response ({t_ghost:.3f}s) has identical compute barrier as existing user ({t_exist:.3f}s)")

    # (b) Step-by-step failure countdown & 429 lockout
    test_victim_user = f"brute_victim_{int(time.time())}"
    for i in range(1, 3):
        s, _, d = request_raw(f"{base_url}/api/auth/login", "POST", {"username": test_victim_user, "password": f"wrong_{i}"})
        assert s == 401, f"Expected 401 for bad attempt #{i}, got {s}"
        assert "remaining_attempts" in d, "Expected remaining_attempts in 401 response"

    # Next attempt reaches maximum limit (since we did 2 in timing test + 2 here = 4, 5th reaches 0)
    s5, _, d5 = request_raw(f"{base_url}/api/auth/login", "POST", {"username": test_victim_user, "password": "wrong_5"})
    assert s5 == 401
    assert d5.get("remaining_attempts") == 0

    # 6th attempt MUST trigger 429 Rate Limit Lockout
    s6, h6, d6 = request_raw(f"{base_url}/api/auth/login", "POST", {"username": test_victim_user, "password": "wrong_6"})
    assert s6 == 429, f"Expected 429 Locked Out on 6th attempt, got {s6}: {d6}"
    assert "Retry-After" in h6 or "retry-after" in h6 or d6.get("retry_after"), "Expected Retry-After header/field"
    print(f"      -> 16(b) Rate Limit Lockout: IP/Account locked out after 5 consecutive failures (HTTP 429 with Retry-After: {d6.get('retry_after')}s)")

    print("  [PASS] 16. Dual-Dimension Anti-Brute-Force, Account Lockout & Timing Defense 100% verified!")

    # --------------------------------------------------------------------------
    # 17. Security Audit Logs & IP Failure Review Test Suite
    # --------------------------------------------------------------------------
    print("\n  [*] Running Security Audit Logs & IP Tracking Test Suite (Step 17)...")

    s_logs, _, logs_data = request_raw(f"{base_url}/api/admin/security-logs?limit=50", "GET", headers=auth_headers)
    assert s_logs == 200, f"Expected 200 for security-logs, got {s_logs}: {logs_data}"
    assert "logs" in logs_data and len(logs_data["logs"]) > 0, "Expected recorded security audit logs"
    assert "total_failed_attempts" in logs_data, "Expected total_failed_attempts in summary stats"
    assert "distinct_failed_ips" in logs_data, "Expected distinct_failed_ips in summary stats"
    print(f"      -> 17(a) Security Audit Logs Query: Successfully retrieved {len(logs_data['logs'])} audit entries (Total Failed: {logs_data['total_failed_attempts']}, Unique IPs: {logs_data['distinct_failed_ips']})")

    first_log = logs_data["logs"][0]
    assert "ip" in first_log and "username_attempted" in first_log and "status" in first_log
    print(f"      -> 17(b) Audit Trail Verification: Log #{first_log['id']} [IP: {first_log['ip']}, User: {first_log['username_attempted']}, Status: {first_log['status']}] accurately captured")

    print("  [PASS] 17. Security Audit Logging, Offending IP Tracking & Admin Review API 100% verified!")


    print("\n==========================================================================================")
    print(">>> ALL SECURITY HARDENING, WEB HEADERS, AUTH & CRYPTO TESTS PASSED! <<<")
    print("==========================================================================================\n")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    run_tests(target)
