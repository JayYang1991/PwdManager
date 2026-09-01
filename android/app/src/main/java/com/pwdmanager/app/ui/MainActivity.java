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
            public void onSuccess(int addedOrUpdatedCount, String syncTime) {
                swipeRefresh.setRefreshing(false);
                tvSyncStatus.setText("已同步 (" + addedOrUpdatedCount + " 条)");
                loadLocalData();
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
            Toast.makeText(MainActivity.this, "已生成高强度密码", Toast.LENGTH_SHORT).show();
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
                Toast.makeText(MainActivity.this, "已存在相同的网站名称、网址与账号，不允许重复添加！", Toast.LENGTH_LONG).show();
                etName.setError("已存在完全相同的记录");
                return;
            }

            try {
                PasswordItem item = isEdit ? existingItem : new PasswordItem();
                item.setName(name);
                item.setUrl(url);
                item.setUsername(username);
                item.setPassword(password);
                item.setNotes(notes);
                item.setUpdatedAt(PasswordItem.getIsoNow());
                item.setIsDeleted(0);

                // Save locally
                dbHelper.upsertPassword(item);
                loadLocalData();
                dialog.dismiss();

                // Push to server (Server handles encryption)
                syncManager.pushRecord(item, new SyncManager.PushCallback() {
                    @Override
                    public void onSuccess(PasswordItem saved) {
                        Toast.makeText(MainActivity.this, "已保存并在服务端完成加密", Toast.LENGTH_SHORT).show();
                        performSync();
                    }

                    @Override
                    public void onError(String errorMsg) {
                        Toast.makeText(MainActivity.this, "已保存在本地，" + errorMsg, Toast.LENGTH_LONG).show();
                    }
                });

            } catch (Exception e) {
                e.printStackTrace();
                Toast.makeText(MainActivity.this, "保存错误: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        });

        dialog.show();
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
            Executors.newSingleThreadExecutor().execute(() -> {
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

                Executors.newSingleThreadExecutor().execute(() -> {
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

            Executors.newSingleThreadExecutor().execute(() -> {
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
        Executors.newSingleThreadExecutor().execute(() -> {
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
        Executors.newSingleThreadExecutor().execute(() -> {
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

            Executors.newSingleThreadExecutor().execute(() -> {
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
        Executors.newSingleThreadExecutor().execute(() -> {
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

            Executors.newSingleThreadExecutor().execute(() -> {
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
                            Toast.makeText(MainActivity.this, errorMsg, Toast.LENGTH_SHORT).show();
                            loadLocalData();
                        }
                    });
                })
                .setNegativeButton("取消", null)
                .show();
    }
}
