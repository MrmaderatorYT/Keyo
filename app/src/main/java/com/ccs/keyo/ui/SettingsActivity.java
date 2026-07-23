package com.ccs.keyo.ui;

import android.content.Intent;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.Toolbar;

import com.ccs.keyo.R;
import com.ccs.keyo.firebase.FirebaseManager;
import com.ccs.keyo.model.PasswordEntry;
import com.ccs.keyo.session.SessionManager;
import com.ccs.keyo.util.AppSettings;
import com.ccs.keyo.util.LocalEntryStore;
import com.ccs.keyo.util.LocalVaultStore;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import com.google.firebase.auth.FirebaseUser;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Налаштування: тема, синхронізація всіх паролів у Firestore,
 * видалення хмарних даних, видалення акаунта.
 */
public class SettingsActivity extends BaseSecureActivity {

    private LinearProgressIndicator progress;
    private MaterialButton syncAllButton;
    private MaterialButton deleteCloudButton;
    private MaterialButton deleteAccountButton;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        Toolbar toolbar = findViewById(R.id.settings_toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        progress = findViewById(R.id.settings_progress);
        syncAllButton = findViewById(R.id.settings_sync_all_button);
        deleteCloudButton = findViewById(R.id.settings_delete_cloud_button);
        deleteAccountButton = findViewById(R.id.settings_delete_account_button);

        setupThemeRadios();
        syncAllButton.setOnClickListener(v -> confirmSyncAll());
        deleteCloudButton.setOnClickListener(v -> confirmDeleteCloudData());
        deleteAccountButton.setOnClickListener(v -> confirmDeleteAccount());
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void setupThemeRadios() {
        RadioGroup group = findViewById(R.id.settings_theme_group);
        RadioButton system = findViewById(R.id.settings_theme_system);
        RadioButton light = findViewById(R.id.settings_theme_light);
        RadioButton dark = findViewById(R.id.settings_theme_dark);

        int mode = AppSettings.getThemeMode(this);
        switch (mode) {
            case AppSettings.THEME_LIGHT:
                light.setChecked(true);
                break;
            case AppSettings.THEME_DARK:
                dark.setChecked(true);
                break;
            case AppSettings.THEME_SYSTEM:
            default:
                system.setChecked(true);
                break;
        }

        group.setOnCheckedChangeListener((g, checkedId) -> {
            int newMode;
            if (checkedId == R.id.settings_theme_light) {
                newMode = AppSettings.THEME_LIGHT;
            } else if (checkedId == R.id.settings_theme_dark) {
                newMode = AppSettings.THEME_DARK;
            } else {
                newMode = AppSettings.THEME_SYSTEM;
            }
            AppSettings.setThemeMode(this, newMode);
        });
    }

    private void confirmSyncAll() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.sync_all_confirm_title)
                .setMessage(R.string.sync_all_confirm_message)
                .setPositiveButton(R.string.action_sync_all_cloud, (d, w) -> syncAllToCloud())
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void syncAllToCloud() {
        FirebaseUser user = FirebaseManager.getInstance().getCurrentUser();
        if (user == null) {
            Toast.makeText(this, R.string.error_not_signed_in, Toast.LENGTH_LONG).show();
            return;
        }
        List<PasswordEntry> entries = LocalEntryStore.loadAll(this, user.getUid());
        if (entries.isEmpty()) {
            Toast.makeText(this, R.string.sync_all_empty, Toast.LENGTH_SHORT).show();
            return;
        }
        setBusy(true);
        AtomicInteger remaining = new AtomicInteger(entries.size());
        AtomicInteger failures = new AtomicInteger(0);
        for (PasswordEntry entry : entries) {
            FirebaseManager.getInstance().saveEntry(entry, new FirebaseManager.Callback<Void>() {
                @Override
                public void onSuccess(Void result) {
                    LocalEntryStore.markCloudSynced(
                            SettingsActivity.this, user.getUid(), entry.getId(), true);
                    if (remaining.decrementAndGet() == 0) {
                        finishSyncAll(failures.get());
                    }
                }

                @Override
                public void onError(@NonNull Exception e) {
                    failures.incrementAndGet();
                    if (remaining.decrementAndGet() == 0) {
                        finishSyncAll(failures.get());
                    }
                }
            });
        }
    }

    private void finishSyncAll(int failures) {
        setBusy(false);
        if (failures == 0) {
            Toast.makeText(this, R.string.sync_all_success, Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this,
                    getString(R.string.sync_all_partial, failures),
                    Toast.LENGTH_LONG).show();
        }
    }

    private void confirmDeleteCloudData() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.delete_cloud_confirm_title)
                .setMessage(R.string.delete_cloud_confirm_message)
                .setPositiveButton(R.string.action_delete_cloud_data, (d, w) -> deleteCloudData())
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void deleteCloudData() {
        FirebaseUser user = FirebaseManager.getInstance().getCurrentUser();
        if (user == null) {
            Toast.makeText(this, R.string.error_not_signed_in, Toast.LENGTH_LONG).show();
            return;
        }
        setBusy(true);
        FirebaseManager.getInstance().deleteAllCloudEntries(
                new FirebaseManager.Callback<Void>() {
                    @Override
                    public void onSuccess(Void result) {
                        LocalEntryStore.markAllCloudSynced(
                                SettingsActivity.this, user.getUid(), false);
                        setBusy(false);
                        Toast.makeText(SettingsActivity.this,
                                R.string.delete_cloud_success, Toast.LENGTH_SHORT).show();
                    }

                    @Override
                    public void onError(@NonNull Exception e) {
                        setBusy(false);
                        Toast.makeText(SettingsActivity.this,
                                getString(R.string.error_delete_cloud, e.getLocalizedMessage()),
                                Toast.LENGTH_LONG).show();
                    }
                });
    }

    private void confirmDeleteAccount() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.delete_account_confirm_title)
                .setMessage(R.string.delete_account_confirm_message)
                .setPositiveButton(R.string.action_delete_account, (d, w) -> deleteAccount())
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void deleteAccount() {
        FirebaseUser user = FirebaseManager.getInstance().getCurrentUser();
        if (user == null) {
            Toast.makeText(this, R.string.error_not_signed_in, Toast.LENGTH_LONG).show();
            return;
        }
        String uid = user.getUid();
        setBusy(true);
        FirebaseManager.getInstance().deleteAccount(new FirebaseManager.Callback<Void>() {
            @Override
            public void onSuccess(Void result) {
                wipeLocalAndExit(uid);
            }

            @Override
            public void onError(@NonNull Exception e) {
                // Навіть якщо Auth delete не вдався (потрібен re-auth),
                // локальні дані все одно чистимо лише після успіху сервера.
                setBusy(false);
                Toast.makeText(SettingsActivity.this,
                        getString(R.string.error_delete_account, e.getLocalizedMessage()),
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    private void wipeLocalAndExit(String uid) {
        LocalEntryStore.clear(this, uid);
        LocalVaultStore.clear(this);
        AppSettings.clear(this);
        SessionManager.getInstance().lock();
        setBusy(false);
        Toast.makeText(this, R.string.delete_account_success, Toast.LENGTH_SHORT).show();
        Intent intent = new Intent(this, LoginActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(intent);
        finish();
    }

    private void setBusy(boolean busy) {
        progress.setVisibility(busy ? View.VISIBLE : View.GONE);
        syncAllButton.setEnabled(!busy);
        deleteCloudButton.setEnabled(!busy);
        deleteAccountButton.setEnabled(!busy);
    }
}
