package com.pwdmanager.app.ui;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.textfield.TextInputEditText;
import com.pwdmanager.app.R;
import com.pwdmanager.app.crypto.CryptoUtils;
import com.pwdmanager.app.db.PasswordDatabaseHelper;
import com.pwdmanager.app.model.PasswordItem;
import com.pwdmanager.app.network.ApiClient;
import com.pwdmanager.app.network.SyncManager;
import org.json.JSONObject;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executors;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import androidx.core.content.FileProvider;

public class MainActivity extends AppCompatActivity implements PasswordAdapter.OnItemActionListener {

    private RecyclerView rvPasswords;
    private PasswordAdapter adapter;
    private SwipeRefreshLayout swipeRefresh;
    private LinearLayout layoutEmpty;
    private EditText etSearch;
    private TextView tvSyncStatus;
    private ImageButton btnSync, btnSettings;
    private FloatingActionButton fabAdd;

    private PasswordDatabaseHelper dbHelper;
    private SyncManager syncManager;
    private String currentSearchQuery = "";
    private final java.util.concurrent.ExecutorService bgExecutor = Executors.newCachedThreadPool();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Security Hardening: Protect against screen capture and task snapshots
        getWindow().setFlags(
            android.view.WindowManager.LayoutParams.FLAG_SECURE,
            android.view.WindowManager.LayoutParams.FLAG_SECURE
        );
        setContentView(R.layout.activity_main);

        dbHelper = PasswordDatabaseHelper.getInstance(this);
        syncManager = new SyncManager(this);

        initViews();
        updateTitleWithVersion();
        setupEvents();

        loadLocalData();

        // Check if token exists, otherwise login in background or prompt settings
        performSync();
    }

    private void initViews() {
        rvPasswords = findViewById(R.id.rvPasswords);
        swipeRefresh = findViewById(R.id.swipeRefresh);
        layoutEmpty = findViewById(R.id.layoutEmpty);
        etSearch = findViewById(R.id.etSearch);
        tvSyncStatus = findViewById(R.id.tvSyncStatus);
        btnSync = findViewById(R.id.btnSync);
        btnSettings = findViewById(R.id.btnSettings);
        fabAdd = findViewById(R.id.fabAdd);

        rvPasswords.setLayoutManager(new LinearLayoutManager(this));
        adapter = new PasswordAdapter(this, this);
        rvPasswords.setAdapter(adapter);
    }

    private void setupEvents() {
        swipeRefresh.setOnRefreshListener(this::performSync);

        btnSync.setOnClickListener(v -> performSync());

        btnSettings.setOnClickListener(v -> showSettingsDialog());

        fabAdd.setOnClickListener(v -> showAddEditDialog(null));

        etSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                currentSearchQuery = s.toString();
                loadLocalData();
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });
    }

    private void loadLocalData() {
        List<PasswordItem> list = dbHelper.getAllActivePasswords(currentSearchQuery);
        adapter.updateData(list);
        if (list.isEmpty()) {
            layoutEmpty.setVisibility(View.VISIBLE);
            rvPasswords.setVisibility(View.GONE);
        } else {
            layoutEmpty.setVisibility(View.GONE);
            rvPasswords.setVisibility(View.VISIBLE);
        }
    }

    private void performSync() {
        tvSyncStatus.setText(R.string.syncing);
        swipeRefresh.setRefreshing(true);

        syncManager.syncWithServer(new SyncManager.SyncCallback() {
            @Override
            public void onSuccess(int addedOrUpdatedCount, long currentGlobalVersion) {
                swipeRefresh.setRefreshing(false);
                tvSyncStatus.setText("已同步 (v" + currentGlobalVersion + ", " + addedOrUpdatedCount + " 条)");
                loadLocalData();
                updateTitleWithVersion();
            }

            @Override
            public void onError(String errorMsg) {
                swipeRefresh.setRefreshing(false);
                tvSyncStatus.setText("同步失败(离线)");
                Toast.makeText(MainActivity.this, errorMsg, Toast.LENGTH_LONG).show();
            }
        });
    }

    private void showAddEditDialog(PasswordItem existingItem) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_add_edit, null);
        builder.setView(dialogView);

        AlertDialog dialog = builder.create();

        TextView tvTitle = dialogView.findViewById(R.id.tvDialogTitle);
        TextInputEditText etName = dialogView.findViewById(R.id.etDialogName);
        TextInputEditText etUrl = dialogView.findViewById(R.id.etDialogUrl);
        TextInputEditText etUsername = dialogView.findViewById(R.id.etDialogUsername);
        com.google.android.material.textfield.TextInputLayout tilPassword = dialogView.findViewById(R.id.tilPassword);
        TextInputEditText etPassword = dialogView.findViewById(R.id.etDialogPassword);
        TextInputEditText etNotes = dialogView.findViewById(R.id.etDialogNotes);
        Button btnGenerate = dialogView.findViewById(R.id.btnGeneratePassword);
        Button btnCancel = dialogView.findViewById(R.id.btnDialogCancel);
        Button btnSave = dialogView.findViewById(R.id.btnDialogSave);

        final boolean isEdit = (existingItem != null);
        tvTitle.setText(isEdit ? R.string.edit_password : R.string.add_password);

        if (isEdit) {
            etName.setText(existingItem.getName());
            etUrl.setText(existingItem.getUrl());
            etUsername.setText(existingItem.getUsername());
            etPassword.setText(existingItem.getPassword());
            etNotes.setText(existingItem.getNotes());
        }

        btnGenerate.setOnClickListener(v -> {
            String gen = CryptoUtils.generateStrongPassword(16);
            etPassword.setText(gen);
            tilPassword.setPasswordVisibilityToggleEnabled(true);
            Toast.makeText(MainActivity.this, "🎲 已生成 16 位高强度随机密码！", Toast.LENGTH_SHORT).show();
        });

        btnCancel.setOnClickListener(v -> dialog.dismiss());

        btnSave.setOnClickListener(v -> {
            String name = etName.getText() != null ? etName.getText().toString().trim() : "";
            String url = etUrl.getText() != null ? etUrl.getText().toString().trim() : "";
            String username = etUsername.getText() != null ? etUsername.getText().toString().trim() : "";
            String password = etPassword.getText() != null ? etPassword.getText().toString() : "";
            String notes = etNotes.getText() != null ? etNotes.getText().toString().trim() : "";

            if (name.isEmpty()) {
                etName.setError("网站名称不能为空");
                return;
            }

            if (password.isEmpty()) {
                etPassword.setError("密码不能为空");
                return;
            }

            // Duplicate validation (Disallow duplicate website name, url and username)
            String excludeId = isEdit && existingItem != null ? existingItem.getId() : null;
            if (dbHelper.existsDuplicate(excludeId, name, url, username)) {
                Toast.makeText(MainActivity.this, "已存在相同的网站名称、网址与账号，不允许重复！", Toast.LENGTH_LONG).show();
                etName.setError("已存在完全相同的记录");
                return;
            }

            btnSave.setEnabled(false);
            btnSave.setText(isEdit ? "正在同步服务端..." : "正在提交服务端...");

            if (!isEdit) {
                // Case 1: Create new password (Must push and encrypt on server first)
                PasswordItem newItem = new PasswordItem();
                newItem.setName(name);
                newItem.setUrl(url);
                newItem.setUsername(username);
                newItem.setPassword(password);
                newItem.setNotes(notes);
                newItem.setCreatedAt(PasswordItem.getIsoNow());
                newItem.setUpdatedAt(PasswordItem.getIsoNow());
                newItem.setIsDeleted(0);

                bgExecutor.execute(() -> {
                    try {
                        ApiClient.HttpResponse res = ApiClient.createPassword(MainActivity.this, newItem);
                        runOnUiThread(() -> {
                            btnSave.setEnabled(true);
                            btnSave.setText(R.string.save_and_push);
                            if (res.isSuccess) {
                                try {
                                    JSONObject obj = new JSONObject(res.body);
                                    PasswordItem saved = PasswordItem.fromJson(obj);
                                    saved.setPassword(password);
                                    long newGv = obj.optLong("global_version", dbHelper.getGlobalVersion() + 1);
                                    dbHelper.setGlobalVersion(newGv);
                                    dbHelper.upsertPassword(saved);
                                    loadLocalData();
                                    updateTitleWithVersion();
                                    dialog.dismiss();
                                    Toast.makeText(MainActivity.this, "已保存 (全局版本已自增至 v" + newGv + ")", Toast.LENGTH_SHORT).show();
                                    performSync();
                                } catch (Exception e) {
                                    newItem.setPassword(password);
                                    dbHelper.upsertPassword(newItem);
                                    loadLocalData();
                                    dialog.dismiss();
                                    Toast.makeText(MainActivity.this, "已保存", Toast.LENGTH_SHORT).show();
                                }
                            } else {
                                String errMsg = parseErrorMessage(res.body, "服务端创建失败");
                                performSync();
                                new AlertDialog.Builder(MainActivity.this)
                                        .setTitle("❌ 服务端保存失败")
                                        .setMessage(errMsg + "\n\n已自动从服务端重新同步最新数据与全局版本号，请核对后重试！")
                                        .setPositiveButton("我知道了", null)
                                        .show();
                            }
                        });
                    } catch (Exception e) {
                        runOnUiThread(() -> {
                            btnSave.setEnabled(true);
                            btnSave.setText(R.string.save_and_push);
                            performSync();
                            Toast.makeText(MainActivity.this, "网络错误: " + e.getMessage() + "\n已自动重新同步服务端数据与版本号", Toast.LENGTH_LONG).show();
                        });
                    }
                });

            } else {
                // Case 2: Edit existing password
                // Must first check server baseline and update server. Only on server success can local DB be modified.
                final PasswordItem itemToUpdate = existingItem;
                final String oldLocalPassword = existingItem.getPassword();
                itemToUpdate.setName(name);
                itemToUpdate.setUrl(url);
                itemToUpdate.setUsername(username);
                itemToUpdate.setPassword(password);
                itemToUpdate.setNotes(notes);
                itemToUpdate.setUpdatedAt(PasswordItem.getIsoNow());
                itemToUpdate.setIsDeleted(0);

                bgExecutor.execute(() -> {
                    try {
                        // Check server baseline for conflict detection
                        ApiClient.HttpResponse checkRes = ApiClient.getSinglePassword(MainActivity.this, itemToUpdate.getId(), true);
                        if (checkRes.isSuccess) {
                            JSONObject serverObj = new JSONObject(checkRes.body);
                            String serverPlain = serverObj.optString("plain_password", "");

                            // Check if server's current password differs from local pre-edit baseline
                            if (!serverPlain.isEmpty() && !serverPlain.equals(oldLocalPassword)) {
                                runOnUiThread(() -> {
                                    btnSave.setEnabled(true);
                                    btnSave.setText(R.string.save_and_push);
                                    showConflictResolutionDialog(itemToUpdate, serverPlain, oldLocalPassword, password, dialog);
                                });
                                return;
                            }
                        }

                        // No conflict detected: Commit update directly to server
                        executeServerUpdate(itemToUpdate, dialog, btnSave);

                    } catch (Exception e) {
                        runOnUiThread(() -> {
                            btnSave.setEnabled(true);
                            btnSave.setText(R.string.save_and_push);
                            Toast.makeText(MainActivity.this, "无法连接服务端: " + e.getMessage() + "\n根据安全策略，必须先成功同步服务端方可保存！", Toast.LENGTH_LONG).show();
                        });
                    }
                });
            }
        });

        dialog.show();
    }

    private void executeServerUpdate(PasswordItem item, AlertDialog editDialog, Button btnSave) {
        long currentGv = dbHelper.getGlobalVersion();
        item.setVersion((int) (currentGv & 0x7FFFFFFF)); // compatibility
        bgExecutor.execute(() -> {
            try {
                JSONObject payload = item.toJson();
                payload.put("version", currentGv);
                payload.put("global_version", currentGv);

                String baseUrl = ApiClient.getServerUrl(MainActivity.this);
                String endpoint = baseUrl + "/api/passwords/" + item.getId();
                ApiClient.HttpResponse updateRes = ApiClient.authenticatedRequest(MainActivity.this, endpoint, "PUT", payload);

                runOnUiThread(() -> {
                    if (btnSave != null) {
                        btnSave.setEnabled(true);
                        btnSave.setText(R.string.save_and_push);
                    }
                    if (updateRes.isSuccess) {
                        try {
                            JSONObject obj = new JSONObject(updateRes.body);
                            PasswordItem updatedItem = PasswordItem.fromJson(obj);
                            updatedItem.setPassword(item.getPassword());
                            long newGv = obj.optLong("global_version", currentGv + 1);
                            dbHelper.setGlobalVersion(newGv);
                            dbHelper.upsertPassword(updatedItem);
                            loadLocalData();
                            if (editDialog != null) editDialog.dismiss();
                            Toast.makeText(MainActivity.this, "修改成功 (全局版本已自增至 v" + newGv + ")，服务端与本地已同步", Toast.LENGTH_SHORT).show();
                            updateTitleWithVersion();
                        } catch (Exception e) {
                            dbHelper.incrementGlobalVersion();
                            dbHelper.upsertPassword(item);
                            loadLocalData();
                            if (editDialog != null) editDialog.dismiss();
                            Toast.makeText(MainActivity.this, "修改成功，服务端与本地已同步", Toast.LENGTH_SHORT).show();
                        }
                        performSync();
                    } else {
                        // Always resync data and version from server on any mutation failure
                        performSync();

                        // Check if it's a version mismatch conflict
                        try {
                            JSONObject errObj = new JSONObject(updateRes.body);
                            String code = errObj.optString("code");
                            if ("VERSION_MISMATCH".equals(code) || "CONCURRENT_CONFLICT".equals(code)) {
                                long sVer = errObj.optLong("server_version", 0L);
                                long cVer = errObj.optLong("client_version", currentGv);
                                new AlertDialog.Builder(MainActivity.this)
                                        .setTitle("⚠️ 全局版本冲突 (Version Mismatch)")
                                        .setMessage("服务端全局版本已更新至 v" + sVer + "，而当前提交版本为 v" + cVer + "。\n服务端已拒绝修改以保护数据一致性。\n\n已自动从服务端重新拉取最新数据与版本号，请核对最新记录后重新编辑！")
                                        .setPositiveButton("我知道了", (d, w) -> {
                                            if (editDialog != null) editDialog.dismiss();
                                        })
                                        .show();
                                return;
                            }
                        } catch (Exception ignored) {}

                        // Server update rejected/failed -> DO NOT modify local DB
                        String errMsg = parseErrorMessage(updateRes.body, "服务端更新拒绝");
                        new AlertDialog.Builder(MainActivity.this)
                                .setTitle("❌ 服务端修改失败")
                                .setMessage(errMsg + "\n\n已自动从服务端重新同步最新数据与全局版本号，请核对后重试！")
                                .setPositiveButton("我知道了", (d, w) -> {
                                    if (editDialog != null) editDialog.dismiss();
                                })
                                .show();
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (btnSave != null) {
                        btnSave.setEnabled(true);
                        btnSave.setText(R.string.save_and_push);
                    }
                    performSync();
                    Toast.makeText(MainActivity.this, "修改失败: " + e.getMessage() + "\n已自动重新同步服务端数据与版本号", Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void updateTitleWithVersion() {
        if (getSupportActionBar() != null) {
            getSupportActionBar().setSubtitle("全局版本: v" + dbHelper.getGlobalVersion());
        }
    }

    private void showConflictResolutionDialog(PasswordItem item, String serverPassword, String localOriginalPassword, String newlyEnteredPassword, AlertDialog editDialog) {
        new AlertDialog.Builder(MainActivity.this)
                .setTitle("⚠️ 发现服务端与本地密码不一致")
                .setMessage("检测到服务端当前保存的密码与本地原密码不一致（可能已在其他设备或网页端修改）：\n\n" +
                        "• 服务端最新密码: " + serverPassword + "\n" +
                        "• APP本地原密码: " + localOriginalPassword + "\n" +
                        "• 您刚才输入的新密码: " + newlyEnteredPassword + "\n\n" +
                        "请选择如何处理此冲突：")
                .setPositiveButton("以新输入密码覆盖服务端与本地", (d, w) -> {
                    item.setPassword(newlyEnteredPassword);
                    executeServerUpdate(item, editDialog, null);
                })
                .setNeutralButton("使用服务端密码覆盖本地", (d, w) -> {
                    item.setPassword(serverPassword);
                    dbHelper.upsertPassword(item);
                    loadLocalData();
                    if (editDialog != null) editDialog.dismiss();
                    Toast.makeText(MainActivity.this, "已使用服务端密码覆盖并更新本地", Toast.LENGTH_LONG).show();
                    performSync();
                })
                .setNegativeButton("取消修改", null)
                .setCancelable(false)
                .show();
    }

    private String parseErrorMessage(String rawBody, String defaultMsg) {
        try {
            JSONObject obj = new JSONObject(rawBody);
            if (obj.has("error")) return obj.getString("error");
            if (obj.has("message")) return obj.getString("message");
        } catch (Exception ignored) {}
        return (rawBody != null && !rawBody.isEmpty()) ? rawBody : defaultMsg;
    }

    private void showSettingsDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_settings, null);
        builder.setView(dialogView);

        AlertDialog dialog = builder.create();

        TextInputEditText etServerUrl = dialogView.findViewById(R.id.etServerUrl);
        TextInputEditText etServerUser = dialogView.findViewById(R.id.etServerUser);
        TextInputEditText etServerPass = dialogView.findViewById(R.id.etServerPass);
        Button btnTest = dialogView.findViewById(R.id.btnTestConnection);
        TextView tvResult = dialogView.findViewById(R.id.tvTestResult);
        Button btnChangePwd = dialogView.findViewById(R.id.btnOpenChangePassword);
        Button btnMasterKey = dialogView.findViewById(R.id.btnOpenMasterKey);
        Button btnExport = dialogView.findViewById(R.id.btnExportBackup);
        Button btnImport = dialogView.findViewById(R.id.btnOpenImport);
        Button btnRotateKey = dialogView.findViewById(R.id.btnOpenRotateKey);
        Button btnCheckAppUpdate = dialogView.findViewById(R.id.btnCheckAppUpdate);
        Button btnCancel = dialogView.findViewById(R.id.btnSettingsCancel);
        Button btnSave = dialogView.findViewById(R.id.btnSettingsSave);

        etServerUrl.setText(ApiClient.getServerUrl(this));
        etServerUser.setText(ApiClient.getUsername(this));
        etServerPass.setText(ApiClient.getPassword(this));

        btnTest.setOnClickListener(v -> {
            String testUrl = etServerUrl.getText() != null ? etServerUrl.getText().toString().trim() : "";
            String testUser = etServerUser.getText() != null ? etServerUser.getText().toString().trim() : "";
            String testPass = etServerPass.getText() != null ? etServerPass.getText().toString().trim() : "";
            tvResult.setText("正在测试鉴权...");
            bgExecutor.execute(() -> {
                boolean ok = ApiClient.login(this, testUrl, testUser, testPass);
                runOnUiThread(() -> {
                    if (ok) {
                        tvResult.setText("鉴权成功 (Token 已获取)");
                        tvResult.setTextColor(getResources().getColor(R.color.success));
                    } else {
                        tvResult.setText("鉴权失败: 用户名/密码错误或无法连接");
                        tvResult.setTextColor(getResources().getColor(R.color.error));
                    }
                });
            });
        });

        btnChangePwd.setOnClickListener(v -> showChangePasswordDialog());
        btnMasterKey.setOnClickListener(v -> showMasterKeyDialog());
        btnExport.setOnClickListener(v -> showExportBackupDialog());
        btnImport.setOnClickListener(v -> showImportBackupDialog());
        btnRotateKey.setOnClickListener(v -> showRotateKeyDialog());
        if (btnCheckAppUpdate != null) {
            btnCheckAppUpdate.setOnClickListener(v -> checkAndInstallAppUpdate());
        }

        btnCancel.setOnClickListener(v -> dialog.dismiss());

        btnSave.setOnClickListener(v -> {
            String newUrl = etServerUrl.getText() != null ? etServerUrl.getText().toString().trim() : "";
            String newUser = etServerUser.getText() != null ? etServerUser.getText().toString().trim() : "";
            String newPass = etServerPass.getText() != null ? etServerPass.getText().toString().trim() : "";

            if (!newUrl.isEmpty() && !newUser.isEmpty() && !newPass.isEmpty()) {
                ApiClient.setServerUrl(this, newUrl);
                ApiClient.setUsername(this, newUser);
                ApiClient.setPassword(this, newPass);
                ApiClient.setAuthToken(this, null); // Clear old token to force fresh login

                bgExecutor.execute(() -> {
                    ApiClient.login(this, newUrl, newUser, newPass);
                    runOnUiThread(() -> {
                        Toast.makeText(MainActivity.this, "配置已更新并已鉴权", Toast.LENGTH_SHORT).show();
                        dialog.dismiss();
                        performSync();
                    });
                });
            }
        });

        dialog.show();
    }

    private void showChangePasswordDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_change_password, null);
        builder.setView(dialogView);
        AlertDialog dialog = builder.create();

        TextInputEditText etOld = dialogView.findViewById(R.id.etCpOldPass);
        TextInputEditText etNew = dialogView.findViewById(R.id.etCpNewPass);
        TextInputEditText etConfirm = dialogView.findViewById(R.id.etCpConfirmPass);
        Button btnCancel = dialogView.findViewById(R.id.btnCpCancel);
        Button btnSave = dialogView.findViewById(R.id.btnCpSave);

        etOld.setText(ApiClient.getPassword(this));

        btnCancel.setOnClickListener(v -> dialog.dismiss());

        btnSave.setOnClickListener(v -> {
            String oldPass = etOld.getText() != null ? etOld.getText().toString() : "";
            String newPass = etNew.getText() != null ? etNew.getText().toString() : "";
            String confirmPass = etConfirm.getText() != null ? etConfirm.getText().toString() : "";

            if (oldPass.isEmpty() || newPass.isEmpty()) {
                Toast.makeText(this, "原密码与新密码均不能为空", Toast.LENGTH_SHORT).show();
                return;
            }
            if (newPass.length() < 6) {
                Toast.makeText(this, "新密码长度不能少于 6 位", Toast.LENGTH_SHORT).show();
                return;
            }
            if (!newPass.equals(confirmPass)) {
                Toast.makeText(this, "两次输入的新密码不一致", Toast.LENGTH_SHORT).show();
                return;
            }

            bgExecutor.execute(() -> {
                try {
                    ApiClient.HttpResponse res = ApiClient.changeAdminPassword(this, oldPass, newPass);
                    runOnUiThread(() -> {
                        if (res.isSuccess) {
                            Toast.makeText(MainActivity.this, "🎉 管理员密码修改成功并已更新本地配置！", Toast.LENGTH_LONG).show();
                            dialog.dismiss();
                        } else {
                            try {
                                JSONObject obj = new JSONObject(res.body);
                                Toast.makeText(MainActivity.this, obj.optString("error", "修改失败"), Toast.LENGTH_LONG).show();
                            } catch (Exception e) {
                                Toast.makeText(MainActivity.this, "修改失败: " + res.body, Toast.LENGTH_LONG).show();
                            }
                        }
                    });
                } catch (Exception e) {
                    runOnUiThread(() -> Toast.makeText(MainActivity.this, "网络错误: " + e.getMessage(), Toast.LENGTH_LONG).show());
                }
            });
        });

        dialog.show();
    }

    private void showMasterKeyDialog() {
        bgExecutor.execute(() -> {
            try {
                ApiClient.HttpResponse res = ApiClient.getMasterKey(this);
                runOnUiThread(() -> {
                    if (res.isSuccess) {
                        try {
                            JSONObject obj = new JSONObject(res.body);
                            String key = obj.getString("private_key");
                            String time = obj.optString("updated_at", "");
                            new AlertDialog.Builder(this)
                                    .setTitle("🔒 服务端主加密私钥")
                                    .setMessage("当前主私钥:\n" + key + "\n\n更新时间:\n" + time)
                                    .setPositiveButton("复制私钥", (d, w) -> {
                                        ClipboardManager cb = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                                        if (cb != null) {
                                            cb.setPrimaryClip(ClipData.newPlainText("MasterKey", key));
                                            Toast.makeText(this, "主私钥已复制到剪贴板", Toast.LENGTH_SHORT).show();
                                        }
                                    })
                                    .setNegativeButton("关闭", null)
                                    .show();
                        } catch (Exception e) {
                            Toast.makeText(this, "解析失败", Toast.LENGTH_SHORT).show();
                        }
                    } else {
                        Toast.makeText(this, "获取私钥失败，请确认管理员权限", Toast.LENGTH_SHORT).show();
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this, "请求失败: " + e.getMessage(), Toast.LENGTH_SHORT).show());
            }
        });
    }

    private void showExportBackupDialog() {
        bgExecutor.execute(() -> {
            try {
                ApiClient.HttpResponse res = ApiClient.exportBackup(this);
                runOnUiThread(() -> {
                    if (res.isSuccess) {
                        String jsonString = res.body;
                        new AlertDialog.Builder(this)
                                .setTitle("📤 全量数据备份已生成")
                                .setMessage("已成功获取服务端全量密文数据与主私钥备份包。\n\n包含记录数与完整性校验通过。")
                                .setPositiveButton("复制备份JSON", (d, w) -> {
                                    ClipboardManager cb = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                                    if (cb != null) {
                                        cb.setPrimaryClip(ClipData.newPlainText("PwdBackup", jsonString));
                                        Toast.makeText(this, "备份 JSON 已复制到剪贴板", Toast.LENGTH_SHORT).show();
                                    }
                                })
                                .setNeutralButton("分享/发送文件", (d, w) -> {
                                    Intent sendIntent = new Intent(Intent.ACTION_SEND);
                                    sendIntent.putExtra(Intent.EXTRA_TEXT, jsonString);
                                    sendIntent.setType("text/plain");
                                    startActivity(Intent.createChooser(sendIntent, "分享密码备份"));
                                })
                                .setNegativeButton("关闭", null)
                                .show();
                    } else {
                        Toast.makeText(this, "导出失败: " + res.body, Toast.LENGTH_LONG).show();
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this, "网络错误: " + e.getMessage(), Toast.LENGTH_LONG).show());
            }
        });
    }

    private void showImportBackupDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_import, null);
        builder.setView(dialogView);
        AlertDialog dialog = builder.create();

        TextInputEditText etKey = dialogView.findViewById(R.id.etImpKey);
        TextInputEditText etJson = dialogView.findViewById(R.id.etImpJson);
        Button btnCancel = dialogView.findViewById(R.id.btnImpCancel);
        Button btnSave = dialogView.findViewById(R.id.btnImpSave);

        btnCancel.setOnClickListener(v -> dialog.dismiss());

        btnSave.setOnClickListener(v -> {
            String customKey = etKey.getText() != null ? etKey.getText().toString().trim() : "";
            String rawJson = etJson.getText() != null ? etJson.getText().toString().trim() : "";

            if (rawJson.isEmpty()) {
                Toast.makeText(this, "请输入要导入的 JSON 备份数据", Toast.LENGTH_SHORT).show();
                return;
            }

            bgExecutor.execute(() -> {
                try {
                    ApiClient.HttpResponse res = ApiClient.importBackup(this, customKey, rawJson);
                    runOnUiThread(() -> {
                        if (res.isSuccess) {
                            try {
                                JSONObject obj = new JSONObject(res.body);
                                int count = obj.optInt("imported_records_count", 0);
                                Toast.makeText(MainActivity.this, "🎉 成功导入并恢复 " + count + " 条密码记录！", Toast.LENGTH_LONG).show();
                                dialog.dismiss();
                                performSync();
                            } catch (Exception e) {
                                Toast.makeText(MainActivity.this, "导入成功", Toast.LENGTH_SHORT).show();
                                dialog.dismiss();
                                performSync();
                            }
                        } else {
                            Toast.makeText(MainActivity.this, "导入失败: " + res.body, Toast.LENGTH_LONG).show();
                        }
                    });
                } catch (Exception e) {
                    runOnUiThread(() -> Toast.makeText(MainActivity.this, "导入错误: " + e.getMessage(), Toast.LENGTH_LONG).show());
                }
            });
        });

        dialog.show();
    }

    private void showRotateKeyDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_rotate_key, null);
        builder.setView(dialogView);
        AlertDialog dialog = builder.create();

        TextInputEditText etOldKey = dialogView.findViewById(R.id.etRotOldKey);
        TextInputEditText etNewKey = dialogView.findViewById(R.id.etRotNewKey);
        Button btnGenKey = dialogView.findViewById(R.id.btnGenRotateKey);
        CheckBox cbReencrypt = dialogView.findViewById(R.id.cbReencryptRecords);
        Button btnCancel = dialogView.findViewById(R.id.btnRotCancel);
        Button btnSave = dialogView.findViewById(R.id.btnRotSave);

        // Fetch current master key to prefill
        bgExecutor.execute(() -> {
            try {
                ApiClient.HttpResponse res = ApiClient.getMasterKey(this);
                if (res.isSuccess) {
                    JSONObject obj = new JSONObject(res.body);
                    String key = obj.getString("private_key");
                    runOnUiThread(() -> etOldKey.setText(key));
                }
            } catch (Exception ignored) {}
        });

        btnGenKey.setOnClickListener(v -> {
            String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~";
            StringBuilder sb = new StringBuilder("AppRotated_");
            Random random = new Random();
            for (int i = 0; i < 24; i++) {
                sb.append(chars.charAt(random.nextInt(chars.length())));
            }
            etNewKey.setText(sb.toString());
        });

        btnCancel.setOnClickListener(v -> dialog.dismiss());

        btnSave.setOnClickListener(v -> {
            String oldKey = etOldKey.getText() != null ? etOldKey.getText().toString().trim() : "";
            String newKey = etNewKey.getText() != null ? etNewKey.getText().toString().trim() : "";
            boolean reencrypt = cbReencrypt.isChecked();

            if (newKey.isEmpty()) {
                Toast.makeText(this, "新主私钥不能为空", Toast.LENGTH_SHORT).show();
                return;
            }

            bgExecutor.execute(() -> {
                try {
                    ApiClient.HttpResponse res = ApiClient.rotateMasterKey(this, oldKey, newKey, reencrypt);
                    runOnUiThread(() -> {
                        if (res.isSuccess) {
                            try {
                                JSONObject obj = new JSONObject(res.body);
                                int count = obj.optInt("reencrypted_records_count", 0);
                                Toast.makeText(MainActivity.this, "🎉 主私钥轮换成功！已重加密 " + count + " 条记录", Toast.LENGTH_LONG).show();
                                dialog.dismiss();
                                performSync();
                            } catch (Exception e) {
                                Toast.makeText(MainActivity.this, "密钥更换成功", Toast.LENGTH_SHORT).show();
                                dialog.dismiss();
                                performSync();
                            }
                        } else {
                            Toast.makeText(MainActivity.this, "轮换失败: " + res.body, Toast.LENGTH_LONG).show();
                        }
                    });
                } catch (Exception e) {
                    runOnUiThread(() -> Toast.makeText(MainActivity.this, "网络错误: " + e.getMessage(), Toast.LENGTH_LONG).show());
                }
            });
        });

        dialog.show();
    }

    @Override
    public void onEdit(PasswordItem item) {
        showAddEditDialog(item);
    }

    @Override
    public void onDelete(PasswordItem item) {
        new AlertDialog.Builder(this)
                .setTitle("确认删除")
                .setMessage("确定要删除「" + item.getName() + "」的记录吗？此操作将同步至服务端。")
                .setPositiveButton("删除", (d, w) -> {
                    syncManager.deleteRecord(item.getId(), new SyncManager.PushCallback() {
                        @Override
                        public void onSuccess(PasswordItem res) {
                            Toast.makeText(MainActivity.this, "已删除并同步", Toast.LENGTH_SHORT).show();
                            loadLocalData();
                            performSync();
                        }

                        @Override
                        public void onError(String errorMsg) {
                            performSync();
                            Toast.makeText(MainActivity.this, "删除失败: " + errorMsg + "\n已自动从服务端重新同步最新数据与版本号", Toast.LENGTH_LONG).show();
                            loadLocalData();
                        }
                    });
                })
                .setNegativeButton("取消", null)
                .show();
    }


        private void checkAndInstallAppUpdate() {
        String baseUrl = ApiClient.getServerUrl(this);
        Toast.makeText(this, "正在检查服务端版本与安装包...", Toast.LENGTH_SHORT).show();

        bgExecutor.execute(() -> {
            try {
                ApiClient.HttpResponse res = ApiClient.authenticatedRequest(this, baseUrl + "/api/health", "GET", null);
                if (!res.isSuccess) {
                    runOnUiThread(() -> Toast.makeText(this, "检查更新失败: 无法连接服务端", Toast.LENGTH_SHORT).show());
                    return;
                }
                JSONObject obj = new JSONObject(res.body);
                String serverVer = obj.optString("version", "2.1.0");

                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    String msg = "• 当前客户端版本: v1.0 (Build 1)\n" +
                            "• 服务端系统版本: v" + serverVer + "\n" +
                            "• 安装包源: " + baseUrl + "/download/app.apk\n\n" +
                            "本项目已配置统一发布签名，支持直接覆盖更新安装。\n是否立即下载并进行更新安装？";
                    new AlertDialog.Builder(this)
                            .setTitle("🚀 检查应用安装包")
                            .setMessage(msg)
                            .setPositiveButton("立即下载并安装", (d, w) -> startDownloadAndInstallApk(baseUrl + "/download/app.apk"))
                            .setNegativeButton("取消", null)
                            .show();
                });
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this, "检查更新失败: " + e.getMessage(), Toast.LENGTH_SHORT).show());
            }
        });
    }

    private void startDownloadAndInstallApk(String apkUrl) {
        Toast.makeText(this, "开始下载最新安装包...", Toast.LENGTH_SHORT).show();
        bgExecutor.execute(() -> {
            File apkFile = null;
            try {
                URL url = new URL(apkUrl);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(60000);
                String token = ApiClient.getAuthToken(this);
                if (token != null) {
                    conn.setRequestProperty("Authorization", "Bearer " + token);
                }
                conn.connect();

                if (conn.getResponseCode() != 200) {
                    throw new IllegalStateException("下载失败，服务端返回 HTTP " + conn.getResponseCode());
                }

                File downloadsDir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                if (downloadsDir == null) downloadsDir = getCacheDir();
                apkFile = new File(downloadsDir, "PwdManager_update.apk");
                if (apkFile.exists()) apkFile.delete();

                try (InputStream is = conn.getInputStream();
                     FileOutputStream fos = new FileOutputStream(apkFile)) {
                    byte[] buffer = new byte[8192];
                    int len;
                    while ((len = is.read(buffer)) != -1) {
                        fos.write(buffer, 0, len);
                    }
                    fos.flush();
                }
                conn.disconnect();

                final File finalApkFile = apkFile;
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    installApk(finalApkFile);
                });

            } catch (Exception e) {
                e.printStackTrace();
                runOnUiThread(() -> Toast.makeText(this, "下载安装包失败: " + e.getMessage(), Toast.LENGTH_LONG).show());
            }
        });
    }

    private void installApk(File apkFile) {
        if (apkFile == null || !apkFile.exists()) {
            Toast.makeText(this, "安装包文件不存在", Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            Intent installIntent = new Intent(Intent.ACTION_VIEW);
            installIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            Uri apkUri;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                apkUri = FileProvider.getUriForFile(
                        this,
                        getPackageName() + ".fileprovider",
                        apkFile
                );
                installIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            } else {
                apkUri = Uri.fromFile(apkFile);
            }

            installIntent.setDataAndType(apkUri, "application/vnd.android.package-archive");
            startActivity(installIntent);
            Toast.makeText(this, "已启动系统安装程序，请确认覆盖安装！", Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            e.printStackTrace();
            new AlertDialog.Builder(this)
                    .setTitle("无法启动安装程序")
                    .setMessage("错误: " + e.getMessage() + "\n若为 Android 8.0+，请确保已授予「安装未知应用」权限。")
                    .setPositiveButton("我知道了", null)
                    .show();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        try {
            bgExecutor.shutdown();
            if (syncManager != null) {
                syncManager.shutdown();
            }
        } catch (Exception ignored) {}
    }

}
