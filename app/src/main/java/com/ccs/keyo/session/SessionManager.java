package com.ccs.keyo.session;

import android.os.SystemClock;

import com.ccs.keyo.crypto.KeyoCryptographer;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Тримає виведений майстер-ключ ЛИШЕ в оперативній пам'яті процесу.
 *
 * Zero-Knowledge інваріанти:
 *  - ключ ніколи не пишеться на диск, у Bundle, у SharedPreferences;
 *  - при блокуванні (вручну, за тайм-аутом або при вбивстві процесу)
 *    байти ключа затираються;
 *  - після тайм-ауту бездіяльності isUnlocked() поверне false, і будь-який
 *    захищений екран перекине користувача на LoginActivity.
 */
public final class SessionManager {

    /** Тайм-аут бездіяльності до автоблокування. */
    public static final long AUTO_LOCK_TIMEOUT_MS = 2 * 60 * 1000; // 2 хвилини

    private static final SessionManager INSTANCE = new SessionManager();

    /** Сирі байти ключа — тримаємо самі, щоб мати змогу їх затерти. */
    private volatile byte[] masterKeyBytes;
    private volatile long lastActivityElapsedMs;

    private SessionManager() {
    }

    public static SessionManager getInstance() {
        return INSTANCE;
    }

    /** Розблокування сховища після успішної верифікації майстер-пароля. */
    public synchronized void unlock(SecretKey masterKey) {
        lock(); // затерти попередній ключ, якщо був
        masterKeyBytes = masterKey.getEncoded();
        touch();
    }

    /** Фіксує активність користувача — відсуває автоблокування. */
    public void touch() {
        lastActivityElapsedMs = SystemClock.elapsedRealtime();
    }

    /** true, поки ключ у пам'яті й тайм-аут не сплив. Інакше — блокує. */
    public synchronized boolean isUnlocked() {
        if (masterKeyBytes == null) {
            return false;
        }
        if (SystemClock.elapsedRealtime() - lastActivityElapsedMs > AUTO_LOCK_TIMEOUT_MS) {
            lock();
            return false;
        }
        return true;
    }

    /** Мілісекунди до автоблокування (для планування перевірки в UI). */
    public long millisUntilLock() {
        long remaining = AUTO_LOCK_TIMEOUT_MS
                - (SystemClock.elapsedRealtime() - lastActivityElapsedMs);
        return Math.max(0, remaining);
    }

    /**
     * @return сесійний ключ або null, якщо сховище заблоковане.
     * SecretKeySpec створюється на вимогу з байтів, якими володіє цей клас.
     */
    public synchronized SecretKey getMasterKey() {
        if (!isUnlocked()) {
            return null;
        }
        return new SecretKeySpec(masterKeyBytes, "AES");
    }

    /** Блокує сховище й затирає ключ у пам'яті. */
    public synchronized void lock() {
        KeyoCryptographer.wipe(masterKeyBytes);
        masterKeyBytes = null;
    }
}
