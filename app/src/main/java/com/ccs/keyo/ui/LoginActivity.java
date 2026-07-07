package com.ccs.keyo.ui;

import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.view.View;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.ccs.keyo.R;
import com.ccs.keyo.crypto.KeyoCryptographer;
import com.ccs.keyo.firebase.FirebaseManager;
import com.ccs.keyo.model.VaultProfile;
import com.ccs.keyo.session.SessionManager;
import com.ccs.keyo.util.LocalVaultStore;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;
import com.google.firebase.auth.FirebaseUser;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.SecretKey;

/**
 * Розблокування сховища.
 *
 * Два незалежні рубежі:
 *  1. Firebase Auth (email + пароль акаунта) — лише доступ до синхронізації.
 *  2. Майстер-пароль — перевіряється ЛОКАЛЬНО через верифікатор
 *     (розшифрування відомої константи). Пароль не передається нікуди.
 */
public class LoginActivity extends BaseSecureActivity {

    private View accountGroup;
    private TextInputLayout emailLayout;
    private TextInputLayout accountPasswordLayout;
    private TextInputLayout masterPasswordLayout;
    private TextInputEditText emailInput;
    private TextInputEditText accountPasswordInput;
    private TextInputEditText masterPasswordInput;
    private MaterialButton unlockButton;
    private MaterialButton createVaultButton;
    private MaterialButton switchAccountButton;
    private LinearProgressIndicator progress;

    private final ExecutorService cryptoExecutor = Executors.newSingleThreadExecutor();

    @Override
    protected boolean requiresUnlock() {
        return false;
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        accountGroup = findViewById(R.id.login_account_group);
        emailLayout = findViewById(R.id.login_email_layout);
        accountPasswordLayout = findViewById(R.id.login_account_password_layout);
        masterPasswordLayout = findViewById(R.id.login_master_password_layout);
        emailInput = findViewById(R.id.login_email);
        accountPasswordInput = findViewById(R.id.login_account_password);
        masterPasswordInput = findViewById(R.id.login_master_password);
        unlockButton = findViewById(R.id.login_unlock_button);
        createVaultButton = findViewById(R.id.login_create_vault_button);
        switchAccountButton = findViewById(R.id.login_switch_account_button);
        progress = findViewById(R.id.login_progress);

        unlockButton.setOnClickListener(v -> onUnlockClicked());
        createVaultButton.setOnClickListener(v ->
                startActivity(new Intent(this, SetupActivity.class)));
        switchAccountButton.setOnClickListener(v -> {
            FirebaseManager.getInstance().signOut();
            LocalVaultStore.clear(this);
            updateAccountUi();
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Якщо сесія жива (напр., повернення з MainActivity за back) — одразу далі
        if (SessionManager.getInstance().isUnlocked()) {
            goToMain();
            return;
        }
        updateAccountUi();
    }

    @Override
    protected void onDestroy() {
        cryptoExecutor.shutdown();
        super.onDestroy();
    }

    private void updateAccountUi() {
        if (!FirebaseManager.isAvailable()) {
            // Firebase не налаштований — показуємо попередження
            accountGroup.setVisibility(View.VISIBLE);
            emailInput.setEnabled(false);
            accountPasswordInput.setEnabled(false);
            unlockButton.setEnabled(false);
            Toast.makeText(this, R.string.firebase_not_configured, Toast.LENGTH_LONG).show();
            return;
        }
        boolean signedIn = FirebaseManager.getInstance().getCurrentUser() != null;
        accountGroup.setVisibility(signedIn ? View.GONE : View.VISIBLE);
        switchAccountButton.setVisibility(signedIn ? View.VISIBLE : View.GONE);
    }

    private void onUnlockClicked() {
        emailLayout.setError(null);
        accountPasswordLayout.setError(null);
        masterPasswordLayout.setError(null);

        char[] masterPassword = charsOf(masterPasswordInput);
        if (masterPassword.length == 0) {
            masterPasswordLayout.setError(getString(R.string.error_master_password_empty));
            return;
        }

        FirebaseUser user = FirebaseManager.getInstance().getCurrentUser();
        if (user != null) {
            loadProfileAndUnlock(user, masterPassword);
            return;
        }

        String email = textOf(emailInput);
        String accountPassword = textOf(accountPasswordInput);
        if (email.isEmpty() || !email.contains("@")) {
            emailLayout.setError(getString(R.string.error_invalid_email));
            KeyoCryptographer.wipe(masterPassword);
            return;
        }
        if (accountPassword.isEmpty()) {
            accountPasswordLayout.setError(getString(R.string.error_account_password_empty));
            KeyoCryptographer.wipe(masterPassword);
            return;
        }

        setBusy(true);
        FirebaseManager.getInstance().signIn(email, accountPassword,
                new FirebaseManager.Callback<FirebaseUser>() {
                    @Override
                    public void onSuccess(FirebaseUser signedInUser) {
                        loadProfileAndUnlock(signedInUser, masterPassword);
                    }

                    @Override
                    public void onError(@NonNull Exception e) {
                        KeyoCryptographer.wipe(masterPassword);
                        setBusy(false);
                        accountPasswordLayout.setError(getString(
                                R.string.error_sign_in_failed, e.getLocalizedMessage()));
                    }
                });
    }

    /** Профіль: спершу локальний кеш (офлайн), інакше Firestore (новий пристрій). */
    private void loadProfileAndUnlock(FirebaseUser user, char[] masterPassword) {
        setBusy(true);
        VaultProfile cached = LocalVaultStore.load(this, user.getUid());
        if (cached != null) {
            deriveAndVerify(cached, masterPassword);
            return;
        }
        FirebaseManager.getInstance().fetchVaultProfile(
                new FirebaseManager.Callback<VaultProfile>() {
                    @Override
                    public void onSuccess(VaultProfile profile) {
                        if (profile == null) {
                            // Акаунт є, а сховища ще немає → на створення
                            KeyoCryptographer.wipe(masterPassword);
                            setBusy(false);
                            startActivity(new Intent(LoginActivity.this, SetupActivity.class));
                            return;
                        }
                        LocalVaultStore.save(LoginActivity.this, user.getUid(), profile);
                        deriveAndVerify(profile, masterPassword);
                    }

                    @Override
                    public void onError(@NonNull Exception e) {
                        KeyoCryptographer.wipe(masterPassword);
                        setBusy(false);
                        Toast.makeText(LoginActivity.this,
                                getString(R.string.error_profile_load, e.getLocalizedMessage()),
                                Toast.LENGTH_LONG).show();
                    }
                });
    }

    /** Argon2id у фоні; перевірка — локальним розшифруванням верифікатора. */
    private void deriveAndVerify(VaultProfile profile, char[] masterPassword) {
        cryptoExecutor.execute(() -> {
            SecretKey key = KeyoCryptographer.deriveKey(
                    masterPassword,
                    KeyoCryptographer.decodeBase64(profile.getKdfSalt()),
                    profile.getKdfMemoryKib(),
                    profile.getKdfIterations(),
                    profile.getKdfParallelism());
            KeyoCryptographer.wipe(masterPassword);

            boolean valid = KeyoCryptographer.verifyMasterKey(key, profile.getVerifier());
            runOnUiThread(() -> {
                setBusy(false);
                if (valid) {
                    SessionManager.getInstance().unlock(key);
                    masterPasswordInput.setText("");
                    goToMain();
                } else {
                    masterPasswordLayout.setError(
                            getString(R.string.error_master_password_wrong));
                }
            });
        });
    }

    private void goToMain() {
        startActivity(new Intent(this, MainActivity.class));
        finish();
    }

    private void setBusy(boolean busy) {
        runOnUiThread(() -> {
            progress.setVisibility(busy ? View.VISIBLE : View.INVISIBLE);
            unlockButton.setEnabled(!busy);
        });
    }

    private static String textOf(TextInputEditText input) {
        return input.getText() == null ? "" : input.getText().toString().trim();
    }

    private static char[] charsOf(TextInputEditText input) {
        Editable text = input.getText();
        if (text == null) {
            return new char[0];
        }
        char[] chars = new char[text.length()];
        text.getChars(0, text.length(), chars, 0);
        return chars;
    }
}
