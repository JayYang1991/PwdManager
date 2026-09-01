package com.pwdmanager.app.network;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import com.pwdmanager.app.db.PasswordDatabaseHelper;
import com.pwdmanager.app.model.PasswordItem;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SyncManager {

    private final Context context;
    private final PasswordDatabaseHelper dbHelper;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    public interface SyncCallback {
        void onSuccess(int addedOrUpdatedCount, long currentGlobalVersion);
        void onError(String errorMsg);
    }

    public interface PushCallback {
        void onSuccess(PasswordItem item);
        void onError(String errorMsg);
    }

    public SyncManager(Context context) {
        this.context = context.getApplicationContext();
        this.dbHelper = PasswordDatabaseHelper.getInstance(this.context);
    }

    public void syncWithServer(SyncCallback callback) {
        executor.execute(() -> {
            try {
                String baseUrl = ApiClient.getServerUrl(context);
                String syncEndpoint = baseUrl + "/api/passwords/sync";

                long clientGlobalVersion = dbHelper.getGlobalVersion();
                List<PasswordItem> localRecords = dbHelper.getAllRecordsIncludingDeleted();
                JSONArray clientArray = new JSONArray();
                for (PasswordItem item : localRecords) {
                    clientArray.put(item.toJson());
                }

                JSONObject requestJson = new JSONObject();
                requestJson.put("client_version", clientGlobalVersion);
                requestJson.put("global_version", clientGlobalVersion);
                requestJson.put("version", clientGlobalVersion);
                requestJson.put("client_records", clientArray);

                ApiClient.HttpResponse response = ApiClient.authenticatedRequest(context, syncEndpoint, "POST", requestJson);

                if (!response.isSuccess) {
                    postError(callback, "服务端返回错误 (" + response.statusCode + "): " + response.body);
                    return;
                }

                JSONObject responseJson = new JSONObject(response.body);
                long serverVersion = responseJson.optLong("server_version", responseJson.optLong("global_version", clientGlobalVersion));
                JSONArray serverRecords = responseJson.optJSONArray("server_records");

                int changedCount = 0;
                if (serverRecords != null) {
                    for (int i = 0; i < serverRecords.length(); i++) {
                        JSONObject rObj = serverRecords.getJSONObject(i);
                        PasswordItem serverItem = PasswordItem.fromJson(rObj);
                        dbHelper.upsertPassword(serverItem);
                        changedCount++;
                    }
                }

                // Global Version Arbitration (Arbitrary gap update success):
                // If server had higher version, update local global version to server version
                // If client had higher version, server adopted it
                long finalVersion = Math.max(clientGlobalVersion, serverVersion);
                dbHelper.setGlobalVersion(finalVersion);

                final int finalCount = changedCount;
                final long finalGv = finalVersion;
                mainHandler.post(() -> {
                    if (callback != null) {
                        callback.onSuccess(finalCount, finalGv);
                    }
                });

            } catch (Exception e) {
                e.printStackTrace();
                postError(callback, "网络同步失败: " + e.getMessage());
            }
        });
    }

    public void pushRecord(PasswordItem item, PushCallback callback) {
        executor.execute(() -> {
            try {
                String baseUrl = ApiClient.getServerUrl(context);
                String endpoint = baseUrl + "/api/passwords";

                JSONObject req = item.toJson();
                req.put("version", dbHelper.getGlobalVersion());

                ApiClient.HttpResponse response = ApiClient.authenticatedRequest(context, endpoint, "POST", req);
                if (response.isSuccess) {
                    JSONObject obj = new JSONObject(response.body);
                    PasswordItem savedItem = PasswordItem.fromJson(obj);
                    savedItem.setPassword(item.getPassword());
                    long newGv = obj.optLong("global_version", dbHelper.getGlobalVersion() + 1);
                    dbHelper.setGlobalVersion(newGv);
                    dbHelper.upsertPassword(savedItem);
                    mainHandler.post(() -> {
                        if (callback != null) callback.onSuccess(savedItem);
                    });
                } else {
                    mainHandler.post(() -> {
                        if (callback != null) callback.onError("推送到服务端失败: " + response.body);
                    });
                }
            } catch (Exception e) {
                e.printStackTrace();
                mainHandler.post(() -> {
                    if (callback != null) callback.onError("推送失败: " + e.getMessage());
                });
            }
        });
    }

    public void deleteRecord(String id, PushCallback callback) {
        executor.execute(() -> {
            try {
                dbHelper.softDeletePassword(id);
                String baseUrl = ApiClient.getServerUrl(context);
                String endpoint = baseUrl + "/api/passwords/" + id;
                ApiClient.HttpResponse response = ApiClient.authenticatedRequest(context, endpoint, "DELETE", null);
                mainHandler.post(() -> {
                    if (callback != null) {
                        if (response.isSuccess) {
                            try {
                                JSONObject obj = new JSONObject(response.body);
                                long newGv = obj.optLong("global_version", dbHelper.getGlobalVersion() + 1);
                                dbHelper.setGlobalVersion(newGv);
                            } catch (Exception ignored) {}
                            callback.onSuccess(null);
                        }
                        else callback.onError("删除请求错误: " + response.body);
                    }
                });
            } catch (Exception e) {
                e.printStackTrace();
                mainHandler.post(() -> {
                    if (callback != null) callback.onError("删除失败: " + e.getMessage());
                });
            }
        });
    }

    private void postError(SyncCallback callback, String message) {
        mainHandler.post(() -> {
            if (callback != null) {
                callback.onError(message);
            }
        });
    }

    public void shutdown() {
        try {
            executor.shutdown();
        } catch (Exception ignored) {}
    }
}
