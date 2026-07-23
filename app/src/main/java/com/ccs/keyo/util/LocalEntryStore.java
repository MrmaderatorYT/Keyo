package com.ccs.keyo.util;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.ccs.keyo.model.PasswordEntry;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Локальне сховище записів (шифротексти) у приватному файлі додатка.
 *
 * Дані вже зашифровані AES-256-GCM майстер-ключем до запису сюди.
 * Файл недоступний іншим додаткам (MODE private) і не потрапляє в бекап
 * (allowBackup=false). Це «надбезпечне» локальне місце за замовчуванням.
 *
 * Структура: entries.json у filesDir/uid/
 */
public final class LocalEntryStore {

    private static final String DIR_NAME = "vault_entries";
    private static final String FILE_NAME = "entries.json";
    private static final String KEY_ENTRIES = "entries";

    private LocalEntryStore() {
    }

    @NonNull
    public static synchronized List<PasswordEntry> loadAll(
            @NonNull Context context, @NonNull String uid) {
        try {
            String raw = readFile(fileFor(context, uid));
            if (raw == null || raw.isEmpty()) {
                return new ArrayList<>();
            }
            JSONObject root = new JSONObject(raw);
            JSONArray arr = root.optJSONArray(KEY_ENTRIES);
            if (arr == null) {
                return new ArrayList<>();
            }
            List<PasswordEntry> list = new ArrayList<>(arr.length());
            for (int i = 0; i < arr.length(); i++) {
                PasswordEntry entry = fromJson(arr.getJSONObject(i));
                if (entry != null) {
                    list.add(entry);
                }
            }
            sortByService(list);
            return list;
        } catch (JSONException e) {
            return new ArrayList<>();
        }
    }

    @Nullable
    public static synchronized PasswordEntry load(
            @NonNull Context context, @NonNull String uid, @NonNull String entryId) {
        for (PasswordEntry e : loadAll(context, uid)) {
            if (entryId.equals(e.getId())) {
                return e;
            }
        }
        return null;
    }

    /**
     * Зберігає або оновлює запис. Якщо id порожній — генерує UUID.
     * @return збережений запис з id
     */
    @NonNull
    public static synchronized PasswordEntry save(
            @NonNull Context context, @NonNull String uid, @NonNull PasswordEntry entry) {
        List<PasswordEntry> list = loadAll(context, uid);
        if (entry.getId() == null || entry.getId().isEmpty()) {
            entry.setId(UUID.randomUUID().toString());
        }
        long now = System.currentTimeMillis();
        if (entry.getCreatedAt() == null) {
            entry.setCreatedAt(new Date(now));
        }
        entry.setUpdatedAt(new Date(now));

        boolean replaced = false;
        for (int i = 0; i < list.size(); i++) {
            if (entry.getId().equals(list.get(i).getId())) {
                // Зберігаємо createdAt зі старого, якщо є
                if (list.get(i).getCreatedAt() != null && entry.getCreatedAt() == null) {
                    entry.setCreatedAt(list.get(i).getCreatedAt());
                }
                list.set(i, entry);
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            list.add(entry);
        }
        persist(context, uid, list);
        return entry;
    }

    public static synchronized void delete(
            @NonNull Context context, @NonNull String uid, @NonNull String entryId) {
        List<PasswordEntry> list = loadAll(context, uid);
        List<PasswordEntry> filtered = new ArrayList<>();
        for (PasswordEntry e : list) {
            if (!entryId.equals(e.getId())) {
                filtered.add(e);
            }
        }
        persist(context, uid, filtered);
    }

    /** Додає віддалені записи, яких ще немає локально (merge без перезапису). */
    public static synchronized void mergeFromRemote(
            @NonNull Context context, @NonNull String uid,
            @NonNull List<PasswordEntry> remoteEntries) {
        List<PasswordEntry> local = loadAll(context, uid);
        boolean changed = false;
        for (PasswordEntry remote : remoteEntries) {
            if (remote.getId() == null || remote.getId().isEmpty()) {
                continue;
            }
            boolean exists = false;
            for (PasswordEntry l : local) {
                if (remote.getId().equals(l.getId())) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                remote.setCloudSynced(true);
                local.add(remote);
                changed = true;
            }
        }
        if (changed) {
            persist(context, uid, local);
        }
    }

    public static synchronized void markCloudSynced(
            @NonNull Context context, @NonNull String uid,
            @NonNull String entryId, boolean synced) {
        List<PasswordEntry> list = loadAll(context, uid);
        for (PasswordEntry e : list) {
            if (entryId.equals(e.getId())) {
                e.setCloudSynced(synced);
                persist(context, uid, list);
                return;
            }
        }
    }

    public static synchronized void markAllCloudSynced(
            @NonNull Context context, @NonNull String uid, boolean synced) {
        List<PasswordEntry> list = loadAll(context, uid);
        for (PasswordEntry e : list) {
            e.setCloudSynced(synced);
        }
        persist(context, uid, list);
    }

    public static synchronized void clear(
            @NonNull Context context, @Nullable String uid) {
        if (uid == null || uid.isEmpty()) {
            File root = new File(context.getFilesDir(), DIR_NAME);
            deleteRecursively(root);
            return;
        }
        File dir = new File(new File(context.getFilesDir(), DIR_NAME), uid);
        deleteRecursively(dir);
    }

    private static void persist(Context context, String uid, List<PasswordEntry> list) {
        sortByService(list);
        try {
            JSONArray arr = new JSONArray();
            for (PasswordEntry e : list) {
                arr.put(toJson(e));
            }
            JSONObject root = new JSONObject();
            root.put(KEY_ENTRIES, arr);
            writeFile(fileFor(context, uid), root.toString());
        } catch (JSONException e) {
            throw new IllegalStateException("Failed to serialize entries", e);
        }
    }

    private static JSONObject toJson(PasswordEntry e) throws JSONException {
        JSONObject o = new JSONObject();
        o.put("id", e.getId() != null ? e.getId() : "");
        o.put("serviceName", e.getServiceName() != null ? e.getServiceName() : "");
        o.put("encryptedUsername", nullToEmpty(e.getEncryptedUsername()));
        o.put("encryptedPassword", nullToEmpty(e.getEncryptedPassword()));
        o.put("encryptedNotes", nullToEmpty(e.getEncryptedNotes()));
        o.put("cloudSynced", e.isCloudSynced());
        o.put("createdAt", e.getCreatedAt() != null ? e.getCreatedAt().getTime() : 0L);
        o.put("updatedAt", e.getUpdatedAt() != null ? e.getUpdatedAt().getTime() : 0L);
        return o;
    }

    @Nullable
    private static PasswordEntry fromJson(JSONObject o) throws JSONException {
        String id = o.optString("id", null);
        if (id == null || id.isEmpty()) {
            return null;
        }
        PasswordEntry e = new PasswordEntry(
                o.optString("serviceName", ""),
                o.optString("encryptedUsername", ""),
                o.optString("encryptedPassword", ""),
                o.optString("encryptedNotes", ""));
        e.setId(id);
        e.setCloudSynced(o.optBoolean("cloudSynced", false));
        long created = o.optLong("createdAt", 0L);
        long updated = o.optLong("updatedAt", 0L);
        if (created > 0) {
            e.setCreatedAt(new Date(created));
        }
        if (updated > 0) {
            e.setUpdatedAt(new Date(updated));
        }
        return e;
    }

    private static void sortByService(List<PasswordEntry> list) {
        Collections.sort(list, Comparator.comparing(
                e -> e.getServiceName() == null ? "" : e.getServiceName().toLowerCase(),
                String::compareTo));
    }

    private static File fileFor(Context context, String uid) {
        File dir = new File(new File(context.getFilesDir(), DIR_NAME), uid);
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        return new File(dir, FILE_NAME);
    }

    @Nullable
    private static String readFile(File file) {
        if (!file.exists()) {
            return null;
        }
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] buf = new byte[(int) file.length()];
            int read = in.read(buf);
            if (read <= 0) {
                return null;
            }
            return new String(buf, 0, read, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    private static void writeFile(File file, String content) {
        try (FileOutputStream out = new FileOutputStream(file, false)) {
            out.write(content.getBytes(StandardCharsets.UTF_8));
            out.getFD().sync();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to write local vault", e);
        }
    }

    private static void deleteRecursively(File file) {
        if (file == null || !file.exists()) {
            return;
        }
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursively(child);
                }
            }
        }
        //noinspection ResultOfMethodCallIgnored
        file.delete();
    }

    private static String nullToEmpty(@Nullable String s) {
        return s == null ? "" : s;
    }
}
