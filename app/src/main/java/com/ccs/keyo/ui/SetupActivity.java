package com.ccs.keyo.ui;

import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.ccs.keyo.R;
import com.ccs.keyo.crypto.KeyoCryptographer;
import com.ccs.keyo.firebase.FirebaseManager;
import com.ccs.keyo.model.VaultProfile;
import com.ccs.keyo.session.SessionManager;
import com.ccs.keyo.util.LocalVaultStore;
import com.ccs.keyo.util.PasswordStrengthChecker;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;
import com.google.firebase.auth.FirebaseUser;

import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.SecretKey;

/**
 * Створення нового сховища:
 *  1) реєстрація акаунта Firebase (email + пароль акаунта — лише для доступу
 *     до синхронізації, він НЕ шифрує дані);
 *  2) створення майстер-пароля (НІКОЛИ не залишає пристрій);
 *  3) Argon2id → майстер-ключ → верифікатор → профіль у Firestore.
 */
public class SetupActivity extends BaseSecureActivity {

    private TextInputLayout emailLayout;
    private TextInputLayout accountPasswordLayout;
    private TextInputLayout masterPasswordLayout;
    private TextInputLayout masterConfirmLayout;
    private TextInputEditText emailInput;
    private TextInputEditText accountPasswordInput;
    private TextInputEditText masterPasswordInput;
    private TextInputEditText masterConfirmInput;
    private LinearProgressIndicator strengthIndicator;
    private TextView strengthLabel;
    private MaterialButton createButton;
    private LinearProgressIndicator progress;

    private final ExecutorService cryptoExecutor = Executors.newSingleThreadExecutor();

    @Override
    protected boolean requiresUnlock() {
        return false; // цей екран існує саме для створення ключа
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_setup);

        emailLayout = findViewById(R.id.setup_email_layout);
        accountPasswordLayout = findViewById(R.id.setup_account_password_layout);
        masterPasswordLayout = findViewById(R.id.setup_master_password_layout);
        masterConfirmLayout = findViewById(R.id.setup_master_confirm_layout);
        emailInput = findViewById(R.id.setup_email);
        accountPasswordInput = findViewById(R.id.setup_account_password);
        masterPasswordInput = findViewById(R.id.setup_master_password);
        masterConfirmInput = findViewById(R.id.setup_master_confirm);
        strengthIndicator = findViewById(R.id.setup_strength_indicator);
        strengthLabel = findViewById(R.id.setup_strength_label);
        createButton = findViewById(R.id.setup_create_button);
        progress = findViewById(R.id.setup_progress);

        masterPasswordInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int st, int c, int a) {
            }

            @Override
            public void onTextChanged(CharSequence s, int st, int b, int c) {
                updateStrengthMeter(s);
            }

            @Override
            public void afterTextChanged(Editable s) {
            }
        });

        createButton.setOnClickListener(v -> onCreateVaultClicked());
    }

    @Override
    protected void onDestroy() {
        cryptoExecutor.shutdown();
        super.onDestroy();
    }

    private void updateStrengthMeter(CharSequence password) {
        int score = PasswordStrengthChecker.score(password);
        strengthIndicator.setMax(PasswordStrengthChecker.STRONG);
        strengthIndicator.setProgressCompat(Math.max(score, password.length() == 0 ? 0 : 1), true);
        int labelRes;
        switch (score) {
            case PasswordStrengthChecker.VERY_WEAK:
                labelRes = R.string.strength_very_weak;
                break;
            case PasswordStrengthChecker.WEAK:
                labelRes = R.string.strength_weak;
                break;
            case PasswordStrengthChecker.FAIR:
                labelRes = R.string.strength_fair;
                break;
            case PasswordStrengthChecker.GOOD:
                labelRes = R.string.strength_good;
                break;
            default:
                labelRes = R.string.strength_strong;
                break;
        }
        strengthLabel.setText(labelRes);
    }

    private void onCreateVaultClicked() {
        emailLayout.setError(null);
        accountPasswordLayout.setError(null);
        masterPasswordLayout.setError(null);
        masterConfirmLayout.setError(null);

        String email = textOf(emailInput);
        String accountPassword = textOf(accountPasswordInput);
        // Майстер-пароль одразу в char[], без зайвих String-копій
        char[] masterPassword = charsOf(masterPasswordInput);
        char[] masterConfirm = charsOf(masterConfirmInput);

        if (email.isEmpty() || !email.contains("@")) {
            emailLayout.setError(getString(R.string.error_invalid_email));
            return;
        }
        if (accountPassword.length() < 8) {
            accountPasswordLayout.setError(getString(R.string.error_account_password_short));
            return;
        }
        // CharBuffer.wrap — без явної String-копії майстер-пароля
        if (!PasswordStrengthChecker.isAcceptableMasterPassword(
                java.nio.CharBuffer.wrap(masterPassword))) {
            masterPasswordLayout.setError(getString(R.string.error_master_password_weak));
            KeyoCryptographer.wipe(masterPassword);
            KeyoCryptographer.wipe(masterConfirm);
            return;
        }
        if (!java.util.Arrays.equals(masterPassword, masterConfirm)) {
            masterConfirmLayout.setError(getString(R.string.error_master_password_mismatch));
            KeyoCryptographer.wipe(masterPassword);
            KeyoCryptographer.wipe(masterConfirm);
            return;
        }
        KeyoCryptographer.wipe(masterConfirm);

        setBusy(true);
        FirebaseManager.getInstance().register(email, accountPassword,
                new FirebaseManager.Callback<FirebaseUser>() {
                    @Override
                    public void onSuccess(FirebaseUser user) {
                        createVault(user, masterPassword);
                    }

                    @Override
                    public void onError(@NonNull Exception e) {
                        KeyoCryptographer.wipe(masterPassword);
                        setBusy(false);
                        emailLayout.setError(getString(
                                R.string.error_registration_failed, e.getLocalizedMessage()));
                    }
                });
    }

    /**
     * Криптографічна частина у фоновому потоці: Argon2id навмисно повільний.
     * Майстер-пароль затирається одразу після деривації ключа.
     */
    private void createVault(FirebaseUser user, char[] masterPassword) {
        cryptoExecutor.execute(() -> {
            try {
                byte[] salt = KeyoCryptographer.generateSalt();
                SecretKey masterKey = KeyoCryptographer.deriveKey(masterPassword, salt);
                KeyoCryptographer.wipe(masterPassword); // пароль більше не потрібен

                String verifier = KeyoCryptographer.createVerifier(masterKey);
                VaultProfile profile = new VaultProfile(
                        KeyoCryptographer.encodeBase64(salt),
                        KeyoCryptographer.KDF_MEMORY_KIB,
                        KeyoCryptographer.KDF_ITERATIONS,
                        KeyoCryptographer.KDF_PARALLELISM,
                        verifier,
                        System.currentTimeMillis());

                runOnUiThread(() -> saveProfile(user, profile, masterKey));
            } catch (GeneralSecurityException e) {
                KeyoCryptographer.wipe(masterPassword);
                runOnUiThread(() -> {
                    setBusy(false);
                    Toast.makeText(this,
                            getString(R.string.error_crypto, e.getLocalizedMessage()),
                            Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void saveProfile(FirebaseUser user, VaultProfile profile, SecretKey masterKey) {
        FirebaseManager.getInstance().saveVaultProfile(profile,
                new FirebaseManager.Callback<Void>() {
                    @Override
                    public void onSuccess(Void result) {
                        LocalVaultStore.save(SetupActivity.this, user.getUid(), profile);
                        SessionManager.getInstance().unlock(masterKey);
                        startActivity(new Intent(SetupActivity.this, MainActivity.class));
                        finishAffinity();
                    }

                    @Override
                    public void onError(@NonNull Exception e) {
                        setBusy(false);
                        Toast.makeText(SetupActivity.this,
                                getString(R.string.error_profile_save, e.getLocalizedMessage()),
                                Toast.LENGTH_LONG).show();
                    }
                });
    }

    private void setBusy(boolean busy) {
        progress.setVisibility(busy ? View.VISIBLE : View.INVISIBLE);
        createButton.setEnabled(!busy);
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
