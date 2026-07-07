package com.ccs.keyo;

import android.app.Application;
import android.util.Log;

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
        try {
            // Плагін google-services попередньо ініціалізує Firebase з json;
            // getInstance() перевірить, чи все OK.
            FirebaseApp.getInstance();
            Log.i(TAG, "Firebase ініціалізовано успішно");
        } catch (IllegalStateException e) {
            // google-services.json відсутній — Firebase не инициализирован
            Log.e(TAG, "Firebase не ініціалізовано: " + e.getMessage()
                    + "\nЕтапи налаштування в README-KEYO.md");
            // Продовжуємо — UI обробить помилку при першому звертанні до Auth/Firestore
        }
    }
}
