package com.pwdmanager.app.db;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import com.pwdmanager.app.model.PasswordItem;
import java.util.ArrayList;
import java.util.List;

public class PasswordDatabaseHelper extends SQLiteOpenHelper {

    private static final String DATABASE_NAME = "pwdmanager_local.db";
    private static final int DATABASE_VERSION = 4;

    public static final String TABLE_PASSWORDS = "passwords";
    public static final String TABLE_META = "meta_config";

    public static final String COLUMN_ID = "id";
    public static final String COLUMN_NAME = "name";
    public static final String COLUMN_URL = "url";
    public static final String COLUMN_USERNAME = "username";
    public static final String COLUMN_PASSWORD = "password";
    public static final String COLUMN_NOTES = "notes";
    public static final String COLUMN_CREATED_AT = "created_at";
    public static final String COLUMN_UPDATED_AT = "updated_at";
    public static final String COLUMN_IS_DELETED = "is_deleted";
    public static final String COLUMN_VERSION = "version";

    public static final String META_KEY = "key";
    public static final String META_VALUE = "value";
    public static final String KEY_GLOBAL_VERSION = "global_version";

    private static PasswordDatabaseHelper instance;

    public static synchronized PasswordDatabaseHelper getInstance(Context context) {
        if (instance == null) {
            instance = new PasswordDatabaseHelper(context.getApplicationContext());
        }
        return instance;
    }

    private PasswordDatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        String createTable = "CREATE TABLE " + TABLE_PASSWORDS + " (" +
                COLUMN_ID + " TEXT PRIMARY KEY, " +
                COLUMN_NAME + " TEXT NOT NULL, " +
                COLUMN_URL + " TEXT, " +
                COLUMN_USERNAME + " TEXT, " +
                COLUMN_PASSWORD + " TEXT, " +
                COLUMN_NOTES + " TEXT, " +
                COLUMN_CREATED_AT + " TEXT NOT NULL, " +
                COLUMN_UPDATED_AT + " TEXT NOT NULL, " +
                COLUMN_IS_DELETED + " INTEGER DEFAULT 0, " +
                COLUMN_VERSION + " INTEGER DEFAULT 0)";
        db.execSQL(createTable);
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_pwd_updated_at ON " + TABLE_PASSWORDS + " (" + COLUMN_UPDATED_AT + ")");

        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_META + " (" +
                META_KEY + " TEXT PRIMARY KEY, " +
                META_VALUE + " TEXT NOT NULL)");
        ContentValues cv = new ContentValues();
        cv.put(META_KEY, KEY_GLOBAL_VERSION);
        cv.put(META_VALUE, "0");
        db.insertWithOnConflict(TABLE_META, null, cv, SQLiteDatabase.CONFLICT_IGNORE);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_META + " (" +
                META_KEY + " TEXT PRIMARY KEY, " +
                META_VALUE + " TEXT NOT NULL)");
        ContentValues cv = new ContentValues();
        cv.put(META_KEY, KEY_GLOBAL_VERSION);
        cv.put(META_VALUE, "0");
        db.insertWithOnConflict(TABLE_META, null, cv, SQLiteDatabase.CONFLICT_IGNORE);

        if (oldVersion < 3) {
            try {
                db.execSQL("ALTER TABLE " + TABLE_PASSWORDS + " ADD COLUMN " + COLUMN_VERSION + " INTEGER DEFAULT 0");
            } catch (Exception ignored) {}
        }
    }

    public synchronized long getGlobalVersion() {
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.query(TABLE_META, new String[]{META_VALUE}, META_KEY + " = ?", new String[]{KEY_GLOBAL_VERSION}, null, null, null);
        long version = 0L;
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                try {
                    version = Long.parseLong(cursor.getString(0));
                } catch (Exception e) {
                    version = 0L;
                }
            }
            cursor.close();
        }
        return version;
    }

    public synchronized void setGlobalVersion(long version) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put(META_KEY, KEY_GLOBAL_VERSION);
        cv.put(META_VALUE, String.valueOf(Math.max(version, 0L)));
        db.insertWithOnConflict(TABLE_META, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public synchronized long incrementGlobalVersion() {
        long next = getGlobalVersion() + 1;
        setGlobalVersion(next);
        return next;
    }

    public synchronized void upsertPassword(PasswordItem item) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(COLUMN_ID, item.getId());
        values.put(COLUMN_NAME, item.getName());
        values.put(COLUMN_URL, item.getUrl());
        values.put(COLUMN_USERNAME, item.getUsername());
        values.put(COLUMN_PASSWORD, item.getPassword());
        values.put(COLUMN_NOTES, item.getNotes());
        values.put(COLUMN_CREATED_AT, item.getCreatedAt());
        values.put(COLUMN_UPDATED_AT, item.getUpdatedAt());
        values.put(COLUMN_IS_DELETED, item.getIsDeleted());
        values.put(COLUMN_VERSION, Math.max(item.getVersion(), 0));

        db.insertWithOnConflict(TABLE_PASSWORDS, null, values, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public synchronized void softDeletePassword(String id) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(COLUMN_IS_DELETED, 1);
        values.put(COLUMN_UPDATED_AT, PasswordItem.getIsoNow());
        db.update(TABLE_PASSWORDS, values, COLUMN_ID + " = ?", new String[]{id});
    }

    public synchronized List<PasswordItem> getAllActivePasswords(String query) {
        List<PasswordItem> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();

        String selection = COLUMN_IS_DELETED + " = 0";
        String[] selectionArgs = null;

        if (query != null && !query.trim().isEmpty()) {
            selection += " AND (" + COLUMN_NAME + " LIKE ? OR " + COLUMN_URL + " LIKE ? OR " + COLUMN_USERNAME + " LIKE ?)";
            String likeArg = "%" + query.trim() + "%";
            selectionArgs = new String[]{likeArg, likeArg, likeArg};
        }

        Cursor cursor = db.query(TABLE_PASSWORDS, null, selection, selectionArgs, null, null, COLUMN_NAME + " COLLATE NOCASE ASC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                list.add(cursorToItem(cursor));
            }
            cursor.close();
        }
        return list;
    }

    public synchronized List<PasswordItem> getAllRecordsIncludingDeleted() {
        List<PasswordItem> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.query(TABLE_PASSWORDS, null, null, null, null, null, null);
        if (cursor != null) {
            while (cursor.moveToNext()) {
                list.add(cursorToItem(cursor));
            }
            cursor.close();
        }
        return list;
    }

    public synchronized boolean existsDuplicate(String excludeId, String name) {
        if (name == null) return false;
        SQLiteDatabase db = getReadableDatabase();
        String n = name.trim();

        String selection = "LOWER(TRIM(" + COLUMN_NAME + ")) = LOWER(?) AND " + COLUMN_IS_DELETED + " = 0";
        List<String> argsList = new ArrayList<>();
        argsList.add(n);

        if (excludeId != null && !excludeId.trim().isEmpty()) {
            selection += " AND " + COLUMN_ID + " != ?";
            argsList.add(excludeId.trim());
        }

        Cursor cursor = db.query(TABLE_PASSWORDS, new String[]{COLUMN_ID}, selection, argsList.toArray(new String[0]), null, null, null);
        boolean exists = false;
        if (cursor != null) {
            exists = cursor.moveToFirst();
            cursor.close();
        }
        return exists;
    }

    public synchronized boolean existsDuplicate(String excludeId, String name, String url, String username) {
        return existsDuplicate(excludeId, name);
    }

    public synchronized PasswordItem getPasswordById(String id) {
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.query(TABLE_PASSWORDS, null, COLUMN_ID + " = ?", new String[]{id}, null, null, null);
        PasswordItem item = null;
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                item = cursorToItem(cursor);
            }
            cursor.close();
        }
        return item;
    }

    private PasswordItem cursorToItem(Cursor cursor) {
        PasswordItem item = new PasswordItem();
        item.setId(cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_ID)));
        item.setName(cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_NAME)));
        item.setUrl(cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_URL)));
        item.setUsername(cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_USERNAME)));
        item.setPassword(cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_PASSWORD)));
        item.setNotes(cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_NOTES)));
        item.setCreatedAt(cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_CREATED_AT)));
        item.setUpdatedAt(cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_UPDATED_AT)));
        item.setIsDeleted(cursor.getInt(cursor.getColumnIndexOrThrow(COLUMN_IS_DELETED)));

        int verIdx = cursor.getColumnIndex(COLUMN_VERSION);
        if (verIdx != -1) {
            item.setVersion(cursor.getInt(verIdx));
        } else {
            item.setVersion(0);
        }

        return item;
    }
}
