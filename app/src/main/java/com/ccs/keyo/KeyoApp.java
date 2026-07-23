package com.ccs.keyo;

import android.app.Application;
import android.util.Log;

import com.ccs.keyo.util.AppSettings;
import com.google.firebase.FirebaseApp;

/**
 * Application клас Keyo.
 *
 * Контролює ініціалізацію Firebase: якщо google-services.json відсутній,
 * Firebase залишиться неініціалізованим, але додаток не впаде — UI покаже
 * помилку про конфіг.
 */
public class KeyoApp extends Application {

    private static final String TAG = "KeyoApp";

    @Override
    public void onCreate() {
        super.onCreate();
        // Тема до будь-якого Activity (по дефолту — системна)
        AppSettings.applyStoredTheme(this);
        try {
            // Плагін google-services попередньо ініціалізує Firebase з json;
            // getInstance() перевірить, чи все OK.
            FirebaseApp.getInstance();
            Log.i(TAG, "Firebase ініціалізовано успішно");
        } catch (IllegalStateException e) {
            // google-services.json відсутній — Firebase не ініціалізовано
            Log.e(TAG, "Firebase не ініціалізовано: " + e.getMessage()
                    + "\nЕтапи налаштування в README.md");
            // Продовжуємо — UI обробить помилку при першому звертанні до Auth/Firestore
        }
    }
}
