package com.ccs.keyo.util;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.Nullable;

import com.ccs.keyo.model.VaultProfile;

/**
 * Локальний кеш VaultProfile у SharedPreferences — для розблокування офлайн.
 *
 * Тут НЕМАЄ секретів: сіль KDF і верифікатор за архітектурою Zero-Knowledge
 * і так зберігаються на сервері та не дають відновити майстер-пароль.
 * Майстер-пароль/ключ сюди ніколи не пишуться.
 */
public final class LocalVaultStore {

    private static final String PREFS_NAME = "keyo_vault_profile";
    private static final String KEY_SALT = "kdf_salt";
    private static final String KEY_MEMORY = "kdf_memory_kib";
    private static final String KEY_ITERATIONS = "kdf_iterations";
    private static final String KEY_PARALLELISM = "kdf_parallelism";
    private static final String KEY_VERIFIER = "verifier";
    private static final String KEY_CREATED_AT = "created_at";
    private static final String KEY_UID = "uid";

    private LocalVaultStore() {
    }

    public static void save(Context context, String uid, VaultProfile profile) {
        prefs(context).edit()
                .putString(KEY_UID, uid)
                .putString(KEY_SALT, profile.getKdfSalt())
                .putInt(KEY_MEMORY, profile.getKdfMemoryKib())
                .putInt(KEY_ITERATIONS, profile.getKdfIterations())
                .putInt(KEY_PARALLELISM, profile.getKdfParallelism())
                .putString(KEY_VERIFIER, profile.getVerifier())
                .putLong(KEY_CREATED_AT, profile.getCreatedAt())
                .apply();
    }

    /** Профіль для даного uid або null (інший акаунт / кешу немає). */
    @Nullable
    public static VaultProfile load(Context context, String uid) {
        SharedPreferences p = prefs(context);
        if (!uid.equals(p.getString(KEY_UID, null))) {
            return null;
        }
        String salt = p.getString(KEY_SALT, null);
        String verifier = p.getString(KEY_VERIFIER, null);
        if (salt == null || verifier == null) {
            return null;
        }
        return new VaultProfile(
                salt,
                p.getInt(KEY_MEMORY, 0),
                p.getInt(KEY_ITERATIONS, 0),
                p.getInt(KEY_PARALLELISM, 0),
                verifier,
                p.getLong(KEY_CREATED_AT, 0));
    }

    public static void clear(Context context) {
        prefs(context).edit().clear().apply();
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }
}
