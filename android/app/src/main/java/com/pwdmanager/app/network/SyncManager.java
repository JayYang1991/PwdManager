package com.pwdmanager.app.network;

import android.content.Context;
import android.content.SharedPreferences;
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

    private static final String PREF_NAME = "pwdmanager_sync_prefs";
    private static final String KEY_LAST_SYNC_TIME = "last_sync_time";

    private final Context context;
    private final PasswordDatabaseHelper dbHelper;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    public interface SyncCallback {
        void onSuccess(int addedOrUpdatedCount, String syncTime);
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

    public String getLastSyncTime() {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return prefs.getString(KEY_LAST_SYNC_TIME, null);
    }

    public void setLastSyncTime(String time) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        prefs.edit().putString(KEY_LAST_SYNC_TIME, time).apply();
    }

    public void syncWithServer(SyncCallback callback) {
        executor.execute(() -> {
            try {
                String baseUrl = ApiClient.getServerUrl(context);
                String syncEndpoint = baseUrl + "/api/passwords/sync";

                List<PasswordItem> localRecords = dbHelper.getAllRecordsIncludingDeleted();
                JSONArray clientArray = new JSONArray();
                for (PasswordItem item : localRecords) {
                    clientArray.put(item.toJson());
                }

                JSONObject requestJson = new JSONObject();
                requestJson.put("last_sync_time", getLastSyncTime());
                requestJson.put("client_records", clientArray);

                ApiClient.HttpResponse response = ApiClient.authenticatedRequest(context, syncEndpoint, "POST", requestJson);

                if (!response.isSuccess) {
                    postError(callback, "服务端返回错误 (" + response.statusCode + "): " + response.body);
                    return;
                }

                JSONObject responseJson = new JSONObject(response.body);
                String serverTime = responseJson.optString("server_time", PasswordItem.getIsoNow());
                JSONArray serverRecords = responseJson.optJSONArray("server_records");

                int changedCount = 0;
                if (serverRecords != null) {
                    for (int i = 0; i < serverRecords.length(); i++) {
                        JSONObject rObj = serverRecords.getJSONObject(i);
                        PasswordItem serverItem = PasswordItem.fromJson(rObj);

                        PasswordItem localItem = dbHelper.getPasswordById(serverItem.getId());
                        if (localItem == null || serverItem.getUpdatedAt().compareTo(localItem.getUpdatedAt()) >= 0) {
                            dbHelper.upsertPassword(serverItem);
                            changedCount++;
                        }
                    }
                }

                setLastSyncTime(serverTime);
                final int finalCount = changedCount;
                mainHandler.post(() -> {
                    if (callback != null) {
                        callback.onSuccess(finalCount, serverTime);
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

                ApiClient.HttpResponse response = ApiClient.authenticatedRequest(context, endpoint, "POST", item.toJson());
                if (response.isSuccess) {
                    JSONObject obj = new JSONObject(response.body);
                    PasswordItem savedItem = PasswordItem.fromJson(obj);
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
                        if (response.isSuccess) callback.onSuccess(null);
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
}
