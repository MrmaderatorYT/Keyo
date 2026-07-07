package com.ccs.keyo.ui;

import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.Toolbar;

import com.ccs.keyo.R;
import com.ccs.keyo.crypto.KeyoCryptographer;
import com.ccs.keyo.firebase.FirebaseManager;
import com.ccs.keyo.model.PasswordEntry;
import com.ccs.keyo.session.SessionManager;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

/**
 * Перегляд/редагування/створення запису. Розшифрування — лише тут і лише
 * сесійним ключем із пам'яті; при збереженні всі чутливі поля знову
 * шифруються перед відправкою у Firestore.
 */
public class DetailActivity extends BaseSecureActivity {

    public static final String EXTRA_ENTRY_ID = "entry_id";
    public static final String EXTRA_SERVICE_NAME = "service_name";
    public static final String EXTRA_ENC_USERNAME = "enc_username";
    public static final String EXTRA_ENC_PASSWORD = "enc_password";
    public static final String EXTRA_ENC_NOTES = "enc_notes";

    private static final long CLIPBOARD_CLEAR_DELAY_MS = 30_000;
    private static final int GENERATED_PASSWORD_LENGTH = 20;

    private TextInputLayout serviceLayout;
    private TextInputEditText serviceInput;
    private TextInputEditText usernameInput;
    private TextInputEditText passwordInput;
    private TextInputEditText notesInput;
    private TextView clipboardWarningText;

    @Nullable
    private String entryId;

    private final Handler clipboardHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_detail);

        Toolbar toolbar = findViewById(R.id.detail_toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        serviceLayout = findViewById(R.id.detail_service_layout);
        serviceInput = findViewById(R.id.detail_service);
        usernameInput = findViewById(R.id.detail_username);
        passwordInput = findViewById(R.id.detail_password);
        notesInput = findViewById(R.id.detail_notes);
        clipboardWarningText = findViewById(R.id.detail_clipboard_warning);
        MaterialButton generateButton = findViewById(R.id.detail_generate_button);
        MaterialButton copyButton = findViewById(R.id.detail_copy_button);
        MaterialButton saveButton = findViewById(R.id.detail_save_button);

        entryId = getIntent().getStringExtra(EXTRA_ENTRY_ID);
        setTitle(entryId == null ? R.string.title_new_entry : R.string.title_edit_entry);
        if (entryId != null) {
            decryptIntoFields();
        }

        generateButton.setOnClickListener(v -> passwordInput.setText(
                KeyoCryptographer.generatePassword(GENERATED_PASSWORD_LENGTH)));
        copyButton.setOnClickListener(v -> copyPasswordToClipboard());
        saveButton.setOnClickListener(v -> onSaveClicked());
    }

    @Override
    protected void onDestroy() {
        clipboardHandler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        if (entryId != null) {
            getMenuInflater().inflate(R.menu.menu_detail, menu);
        }
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        if (item.getItemId() == R.id.action_delete) {
            confirmDelete();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    /** Розшифрування збережених полів для редагування. */
    private void decryptIntoFields() {
        SecretKey key = SessionManager.getInstance().getMasterKey();
        if (key == null) {
            finish(); // сесію заблоковано — BaseSecureActivity перенаправить
            return;
        }
        serviceInput.setText(getIntent().getStringExtra(EXTRA_SERVICE_NAME));
        usernameInput.setText(decryptOrEmpty(
                getIntent().getStringExtra(EXTRA_ENC_USERNAME), key));
        passwordInput.setText(decryptOrEmpty(
                getIntent().getStringExtra(EXTRA_ENC_PASSWORD), key));
        notesInput.setText(decryptOrEmpty(
                getIntent().getStringExtra(EXTRA_ENC_NOTES), key));
    }

    private String decryptOrEmpty(@Nullable String encrypted, SecretKey key) {
        if (encrypted == null || encrypted.isEmpty()) {
            return "";
        }
        try {
            return KeyoCryptographer.decryptWithKey(encrypted, key);
        } catch (GeneralSecurityException e) {
            Toast.makeText(this, R.string.decrypt_error_placeholder, Toast.LENGTH_SHORT).show();
            return "";
        }
    }

    private void onSaveClicked() {
        serviceLayout.setError(null);
        String service = textOf(serviceInput);
        if (service.isEmpty()) {
            serviceLayout.setError(getString(R.string.error_service_empty));
            return;
        }

        SecretKey key = SessionManager.getInstance().getMasterKey();
        if (key == null) {
            return; // автоблокування спрацює саме
        }
        try {
            // Zero-Knowledge: шифруємо ВСІ чутливі поля перед відправкою
            PasswordEntry entry = new PasswordEntry(
                    service,
                    KeyoCryptographer.encryptWithKey(textOf(usernameInput), key),
                    KeyoCryptographer.encryptWithKey(textOf(passwordInput), key),
                    KeyoCryptographer.encryptWithKey(textOf(notesInput), key));
            entry.setId(entryId);

            FirebaseManager.getInstance().saveEntry(entry,
                    new FirebaseManager.Callback<Void>() {
                        @Override
                        public void onSuccess(Void result) {
                            Toast.makeText(DetailActivity.this,
                                    R.string.entry_saved, Toast.LENGTH_SHORT).show();
                            finish();
                        }

                        @Override
                        public void onError(@NonNull Exception e) {
                            Toast.makeText(DetailActivity.this,
                                    getString(R.string.error_entry_save,
                                            e.getLocalizedMessage()),
                                    Toast.LENGTH_LONG).show();
                        }
                    });
        } catch (GeneralSecurityException e) {
            Toast.makeText(this, getString(R.string.error_crypto, e.getLocalizedMessage()),
                    Toast.LENGTH_LONG).show();
        }
    }

    private void confirmDelete() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.delete_confirm_title)
                .setMessage(R.string.delete_confirm_message)
                .setPositiveButton(R.string.delete, (dialog, which) ->
                        FirebaseManager.getInstance().deleteEntry(entryId,
                                new FirebaseManager.Callback<Void>() {
                                    @Override
                                    public void onSuccess(Void result) {
                                        finish();
                                    }

                                    @Override
                                    public void onError(@NonNull Exception e) {
                                        Toast.makeText(DetailActivity.this,
                                                getString(R.string.error_entry_delete,
                                                        e.getLocalizedMessage()),
                                                Toast.LENGTH_LONG).show();
                                    }
                                }))
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    /**
     * Копіювання пароля: позначаємо кліп як чутливий (без прев'ю на API 33+)
     * і автоматично очищаємо буфер обміну через 30 секунд.
     */
    private void copyPasswordToClipboard() {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (clipboard == null) {
            return;
        }
        ClipData clip = ClipData.newPlainText("Keyo", textOf(passwordInput));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            PersistableBundle extras = new PersistableBundle();
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
            clip.getDescription().setExtras(extras);
        }
        clipboard.setPrimaryClip(clip);
        Toast.makeText(this, R.string.password_copied, Toast.LENGTH_SHORT).show();

        clipboardWarningText.setVisibility(View.VISIBLE);

        clipboardHandler.removeCallbacksAndMessages(null);
        clipboardHandler.postDelayed(() -> {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                clipboard.clearPrimaryClip();
            } else {
                clipboard.setPrimaryClip(ClipData.newPlainText("", ""));
            }
            clipboardWarningText.setVisibility(View.GONE);
        }, CLIPBOARD_CLEAR_DELAY_MS);
    }

    private static String textOf(TextInputEditText input) {
        return input.getText() == null ? "" : input.getText().toString().trim();
    }
}
