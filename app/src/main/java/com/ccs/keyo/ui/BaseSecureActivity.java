package com.ccs.keyo.ui;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.MotionEvent;
import android.view.WindowManager;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.ccs.keyo.session.SessionManager;

/**
 * Базовий клас усіх екранів Keyo. Реалізує Android-специфічний захист:
 *
 *  1. FLAG_SECURE — блокує скріншоти, запис екрана та показ вмісту
 *     у списку недавніх додатків (recents). Увімкнено для ВСІХ екранів,
 *     включно з екранами введення паролів.
 *
 *  2. Автоблокування за тайм-аутом бездіяльності:
 *     - кожен дотик користувача продовжує сесію (dispatchTouchEvent);
 *     - Handler перевіряє момент спливання тайм-ауту, поки екран видимий;
 *     - при поверненні з фону onResume() перевіряє стан сесії —
 *       якщо тайм-аут сплив у фоні, ключ уже затерто і користувача
 *       перекидає на LoginActivity.
 */
public abstract class BaseSecureActivity extends AppCompatActivity {

    private final Handler lockHandler = new Handler(Looper.getMainLooper());
    private final Runnable lockCheck = this::enforceLock;

    /** Екрани входу/налаштування повертають false — вони доступні без ключа. */
    protected boolean requiresUnlock() {
        return true;
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Захист від скріншотів і витоку вмісту через recents/запис екрана
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);
    }

    @Override
    protected void onResume() {
        super.onResume();
        enforceLock();
        scheduleLockCheck();
    }

    @Override
    protected void onPause() {
        lockHandler.removeCallbacks(lockCheck);
        super.onPause();
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent ev) {
        if (requiresUnlock()) {
            SessionManager.getInstance().touch();
            scheduleLockCheck();
        }
        return super.dispatchTouchEvent(ev);
    }

    /** Якщо сесію заблоковано — назад на екран введення майстер-пароля. */
    private void enforceLock() {
        if (requiresUnlock() && !SessionManager.getInstance().isUnlocked()) {
            Intent intent = new Intent(this, LoginActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            finish();
        }
    }

    private void scheduleLockCheck() {
        if (!requiresUnlock()) {
            return;
        }
        lockHandler.removeCallbacks(lockCheck);
        // +50 мс, щоб перевірка гарантовано відбулась після спливання тайм-ауту
        lockHandler.postDelayed(lockCheck,
                SessionManager.getInstance().millisUntilLock() + 50);
    }
}
