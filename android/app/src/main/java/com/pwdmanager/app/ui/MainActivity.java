package com.pwdmanager.app.ui;

import android.app.AlertDialog;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Button;
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
import java.util.List;
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
