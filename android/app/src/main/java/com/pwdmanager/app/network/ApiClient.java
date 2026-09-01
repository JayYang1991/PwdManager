package com.pwdmanager.app.network;

import android.content.Context;
import android.content.SharedPreferences;
import com.pwdmanager.app.model.PasswordItem;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class ApiClient {

    private static final String PREF_NAME = "pwdmanager_prefs";
    private static final String KEY_SERVER_URL = "server_url";
    private static final String KEY_USERNAME = "username";
    private static final String KEY_PASSWORD = "password";
    private static final String KEY_AUTH_TOKEN = "auth_token";

    public static final String DEFAULT_SERVER_URL = "http://192.168.122.100:8000";
    public static final String DEFAULT_USERNAME = "jason";
    public static final String DEFAULT_PASSWORD = "admin@1234";

    public static String getServerUrl(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return prefs.getString(KEY_SERVER_URL, DEFAULT_SERVER_URL);
    }

    public static void setServerUrl(Context context, String url) {
        if (url != null) {
            url = url.trim().replaceAll("/+$", "");
        }
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        prefs.edit().putString(KEY_SERVER_URL, url).apply();
    }

    public static String getUsername(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return prefs.getString(KEY_USERNAME, DEFAULT_USERNAME);
    }

    public static void setUsername(Context context, String username) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        prefs.edit().putString(KEY_USERNAME, username).apply();
    }

    public static String getPassword(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return prefs.getString(KEY_PASSWORD, DEFAULT_PASSWORD);
    }

    public static void setPassword(Context context, String password) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        prefs.edit().putString(KEY_PASSWORD, password).apply();
    }

    public static String getAuthToken(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return prefs.getString(KEY_AUTH_TOKEN, null);
    }

    public static void setAuthToken(Context context, String token) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        prefs.edit().putString(KEY_AUTH_TOKEN, token).apply();
    }

    public static class HttpResponse {
        public final int statusCode;
        public final String body;
        public final boolean isSuccess;

        public HttpResponse(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
            this.isSuccess = (statusCode >= 200 && statusCode < 300);
        }
    }

    public static synchronized boolean login(Context context, String serverUrl, String user, String pass) {
        try {
            JSONObject loginJson = new JSONObject();
            loginJson.put("username", user);
            loginJson.put("password", pass);

            HttpResponse res = requestRaw(serverUrl + "/api/auth/login", "POST", loginJson, null);
            if (res.isSuccess) {
                JSONObject obj = new JSONObject(res.body);
                String token = obj.getString("token");
                setServerUrl(context, serverUrl);
                setUsername(context, user);
                setPassword(context, pass);
                setAuthToken(context, token);
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static HttpResponse authenticatedRequest(Context context, String urlString, String method, JSONObject jsonBody) throws Exception {
        String token = getAuthToken(context);
        if (token == null || token.isEmpty()) {
            boolean ok = login(context, getServerUrl(context), getUsername(context), getPassword(context));
            if (!ok) {
                throw new IllegalStateException("鉴权失败，请检查服务器地址、用户名及密码");
            }
            token = getAuthToken(context);
        }

        HttpResponse response = requestRaw(urlString, method, jsonBody, token);
        if (response.statusCode == 401) {
            // Token expired or invalid, try relogin once
            boolean ok = login(context, getServerUrl(context), getUsername(context), getPassword(context));
            if (ok) {
                token = getAuthToken(context);
                response = requestRaw(urlString, method, jsonBody, token);
            }
        }
        return response;
    }

    public static HttpResponse requestRaw(String urlString, String method, JSONObject jsonBody, String token) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try {
            conn.setRequestMethod(method);
            conn.setConnectTimeout(6000);
            conn.setReadTimeout(8000);
            conn.setRequestProperty("Accept", "application/json");

            if (token != null && !token.isEmpty()) {
                conn.setRequestProperty("Authorization", "Bearer " + token);
                conn.setRequestProperty("X-Auth-Token", token);
            }

            if (jsonBody != null && ("POST".equals(method) || "PUT".equals(method))) {
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                byte[] outputBytes = jsonBody.toString().getBytes("UTF-8");
                conn.setFixedLengthStreamingMode(outputBytes.length);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(outputBytes);
                    os.flush();
                }
            }

            int responseCode = conn.getResponseCode();
            InputStream is = (responseCode >= 200 && responseCode < 400) ? conn.getInputStream() : conn.getErrorStream();

            StringBuilder sb = new StringBuilder();
            if (is != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line);
                    }
                }
            }

            return new HttpResponse(responseCode, sb.toString());
        } finally {
            conn.disconnect();
        }
    }

    // --- Password CRUD Server Operations ---

    public static HttpResponse createPassword(Context context, PasswordItem item) throws Exception {
        String url = getServerUrl(context) + "/api/passwords";
        return authenticatedRequest(context, url, "POST", item.toJson());
    }

    public static HttpResponse updatePassword(Context context, PasswordItem item) throws Exception {
        String url = getServerUrl(context) + "/api/passwords/" + item.getId();
        return authenticatedRequest(context, url, "PUT", item.toJson());
    }

    public static HttpResponse getSinglePassword(Context context, String id, boolean decrypt) throws Exception {
        String url = getServerUrl(context) + "/api/passwords/" + id + (decrypt ? "?decrypt=1" : "");
        return authenticatedRequest(context, url, "GET", null);
    }

    public static HttpResponse deletePassword(Context context, String id) throws Exception {
        String url = getServerUrl(context) + "/api/passwords/" + id;
        return authenticatedRequest(context, url, "DELETE", null);
    }

    // --- Admin Feature APIs ---

    public static HttpResponse changeAdminPassword(Context context, String oldPassword, String newPassword) throws Exception {
        String url = getServerUrl(context) + "/api/auth/change-password";
        JSONObject body = new JSONObject();
        body.put("old_password", oldPassword);
        body.put("new_password", newPassword);
        HttpResponse res = authenticatedRequest(context, url, "POST", body);
        if (res.isSuccess) {
            JSONObject obj = new JSONObject(res.body);
            if (obj.has("token")) {
                setAuthToken(context, obj.getString("token"));
            }
            setPassword(context, newPassword);
        }
        return res;
    }

    public static HttpResponse getMasterKey(Context context) throws Exception {
        String url = getServerUrl(context) + "/api/admin/key";
        return authenticatedRequest(context, url, "GET", null);
    }

    public static HttpResponse rotateMasterKey(Context context, String oldKey, String newKey, boolean reencrypt) throws Exception {
        String url = getServerUrl(context) + "/api/admin/rotate-key";
        JSONObject body = new JSONObject();
        body.put("old_key", oldKey);
        body.put("new_key", newKey);
        body.put("reencrypt_records", reencrypt);
        return authenticatedRequest(context, url, "POST", body);
    }

    public static HttpResponse exportBackup(Context context) throws Exception {
        String url = getServerUrl(context) + "/api/admin/export";
        return authenticatedRequest(context, url, "GET", null);
    }

    public static HttpResponse importBackup(Context context, String customPrivateKey, String rawJsonData) throws Exception {
        String url = getServerUrl(context) + "/api/admin/import";
        JSONObject payload = new JSONObject();
        if (rawJsonData.trim().startsWith("{")) {
            JSONObject parsed = new JSONObject(rawJsonData);
            if (customPrivateKey != null && !customPrivateKey.trim().isEmpty()) {
                payload.put("private_key", customPrivateKey.trim());
            } else if (parsed.has("private_key")) {
                payload.put("private_key", parsed.getString("private_key"));
            }
            if (parsed.has("records")) {
                payload.put("records", parsed.getJSONArray("records"));
            }
        } else if (rawJsonData.trim().startsWith("[")) {
            if (customPrivateKey != null && !customPrivateKey.trim().isEmpty()) {
                payload.put("private_key", customPrivateKey.trim());
            }
            payload.put("records", new JSONArray(rawJsonData));
        } else {
            throw new IllegalArgumentException("请输入合法的 JSON 格式备份数据");
        }
        return authenticatedRequest(context, url, "POST", payload);
    }
}
