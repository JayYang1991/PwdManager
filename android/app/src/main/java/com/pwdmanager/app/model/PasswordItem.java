package com.pwdmanager.app.model;

import org.json.JSONException;
import org.json.JSONObject;
import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;

public class PasswordItem implements Serializable {
    private String id;
    private String name;
    private String url;
    private String username;
    private String password;
    private String notes;
    private String createdAt;
    private String updatedAt;
    private int isDeleted;
    private int version;

    public PasswordItem() {
        this.id = UUID.randomUUID().toString();
        this.name = "";
        this.url = "";
        this.username = "";
        this.password = "";
        this.notes = "";
        String now = getIsoNow();
        this.createdAt = now;
        this.updatedAt = now;
        this.isDeleted = 0;
        this.version = 0;
    }

    public static String getIsoNow() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(new Date());
    }

    public static PasswordItem fromJson(JSONObject json) {
        PasswordItem item = new PasswordItem();
        item.id = json.optString("id", UUID.randomUUID().toString());
        item.name = json.optString("name", "");
        item.url = json.optString("url", "");
        item.username = json.optString("username", "");
        item.password = json.optString("plain_password", json.optString("password", ""));
        item.notes = json.optString("notes", "");
        item.createdAt = json.optString("created_at", getIsoNow());
        item.updatedAt = json.optString("updated_at", getIsoNow());
        item.isDeleted = json.optInt("is_deleted", 0);
        item.version = json.optInt("version", 0);
        return item;
    }

    public JSONObject toJson() {
        JSONObject json = new JSONObject();
        try {
            json.put("id", id);
            json.put("name", name);
            json.put("url", url);
            json.put("username", username);
            json.put("password", password);
            json.put("notes", notes);
            json.put("created_at", createdAt);
            json.put("updated_at", updatedAt);
            json.put("is_deleted", isDeleted);
            json.put("version", version);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return json;
    }

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }

    public String getCreatedAt() { return createdAt; }
    public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }

    public String getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(String updatedAt) { this.updatedAt = updatedAt; }

    public int getIsDeleted() { return isDeleted; }
    public void setIsDeleted(int isDeleted) { this.isDeleted = isDeleted; }

    public int getVersion() { return version; }
    public void setVersion(int version) { this.version = version; }
}
