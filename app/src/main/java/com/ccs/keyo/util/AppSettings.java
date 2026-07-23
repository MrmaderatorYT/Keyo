package com.ccs.keyo.util;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatDelegate;

/**
 * Користувацькі налаштування Keyo (тема, прапори згоди).
 * Секрети сюди не пишуться.
 */
public final class AppSettings {

    public static final int THEME_SYSTEM = 0;
    public static final int THEME_LIGHT = 1;
    public static final int THEME_DARK = 2;

    private static final String PREFS_NAME = "keyo_settings";
    private static final String KEY_THEME = "theme_mode";
    private static final String KEY_DATA_CONSENT_ACK = "data_consent_acknowledged";

    private AppSettings() {
    }

    /** По дефолту — системна тема. */
    public static int getThemeMode(@NonNull Context context) {
        return prefs(context).getInt(KEY_THEME, THEME_SYSTEM);
    }

    public static void setThemeMode(@NonNull Context context, int mode) {
        prefs(context).edit().putInt(KEY_THEME, mode).apply();
        applyThemeMode(mode);
    }

    public static void applyThemeMode(int mode) {
        int nightMode;
        switch (mode) {
            case THEME_LIGHT:
                nightMode = AppCompatDelegate.MODE_NIGHT_NO;
                break;
            case THEME_DARK:
                nightMode = AppCompatDelegate.MODE_NIGHT_YES;
                break;
            case THEME_SYSTEM:
            default:
                nightMode = AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM;
                break;
        }
        AppCompatDelegate.setDefaultNightMode(nightMode);
    }

    public static void applyStoredTheme(@NonNull Context context) {
        applyThemeMode(getThemeMode(context));
    }

    public static boolean isDataConsentAcknowledged(@NonNull Context context) {
        return prefs(context).getBoolean(KEY_DATA_CONSENT_ACK, false);
    }

    public static void setDataConsentAcknowledged(@NonNull Context context, boolean value) {
        prefs(context).edit().putBoolean(KEY_DATA_CONSENT_ACK, value).apply();
    }

    public static void clear(@NonNull Context context) {
        // Не чіпаємо тему — це preference пристрою, не акаунта
        prefs(context).edit().remove(KEY_DATA_CONSENT_ACK).apply();
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext()
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }
}
