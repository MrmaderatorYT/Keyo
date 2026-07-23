package com.ccs.keyo.ui;

import android.content.Intent;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.Toolbar;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.ccs.keyo.R;
import com.ccs.keyo.firebase.FirebaseManager;
import com.ccs.keyo.model.PasswordEntry;
import com.ccs.keyo.session.SessionManager;
import com.ccs.keyo.util.LocalEntryStore;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.firebase.auth.FirebaseUser;

import java.util.List;

/**
 * Список збережених паролів. Джерело правди — локальне сховище.
 * При старті підтягуємо з Firestore записи, яких ще немає локально
 * (міграція / інший пристрій). Long-press → bottom sheet: sync з хмарою.
 */
public class MainActivity extends BaseSecureActivity {

    private PasswordEntryAdapter adapter;
    private TextView emptyView;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar toolbar = findViewById(R.id.main_toolbar);
        setSupportActionBar(toolbar);

        emptyView = findViewById(R.id.main_empty_view);
        RecyclerView recyclerView = findViewById(R.id.main_recycler);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));
        adapter = new PasswordEntryAdapter(
                entry -> openDetail(entry),
                entry -> showEntryActions(entry));
        recyclerView.setAdapter(adapter);

        FloatingActionButton fab = findViewById(R.id.main_fab_add);
        fab.setOnClickListener(v ->
                startActivity(new Intent(this, DetailActivity.class)));
    }

    @Override
    protected void onStart() {
        super.onStart();
        refreshLocalList();
        pullRemoteIfNeeded();
    }

    private void refreshLocalList() {
        FirebaseUser user = FirebaseManager.getInstance().getCurrentUser();
        if (user == null) {
            goToLogin();
            return;
        }
        List<PasswordEntry> entries = LocalEntryStore.loadAll(this, user.getUid());
        adapter.submit(entries);
        emptyView.setVisibility(entries.isEmpty() ? View.VISIBLE : View.GONE);
    }

    /** Підтягує записи з Firestore, яких ще немає локально. */
    private void pullRemoteIfNeeded() {
        if (!FirebaseManager.isAvailable()
                || FirebaseManager.getInstance().getCurrentUser() == null) {
            return;
        }
        FirebaseManager.getInstance().fetchEntries(
                new FirebaseManager.Callback<List<PasswordEntry>>() {
                    @Override
                    public void onSuccess(List<PasswordEntry> remote) {
                        FirebaseUser user = FirebaseManager.getInstance().getCurrentUser();
                        if (user == null) {
                            return;
                        }
                        LocalEntryStore.mergeFromRemote(
                                MainActivity.this, user.getUid(), remote);
                        // Позначаємо локальні, що збігаються з remote, як synced
                        for (PasswordEntry r : remote) {
                            if (r.getId() != null) {
                                PasswordEntry local = LocalEntryStore.load(
                                        MainActivity.this, user.getUid(), r.getId());
                                if (local != null && !local.isCloudSynced()) {
                                    LocalEntryStore.markCloudSynced(
                                            MainActivity.this, user.getUid(),
                                            r.getId(), true);
                                }
                            }
                        }
                        refreshLocalList();
                    }

                    @Override
                    public void onError(@NonNull Exception e) {
                        // Офлайн / немає хмарних даних — не критично, локальний список уже показаний
                    }
                });
    }

    private void openDetail(PasswordEntry entry) {
        Intent intent = new Intent(this, DetailActivity.class);
        intent.putExtra(DetailActivity.EXTRA_ENTRY_ID, entry.getId());
        intent.putExtra(DetailActivity.EXTRA_SERVICE_NAME, entry.getServiceName());
        intent.putExtra(DetailActivity.EXTRA_ENC_USERNAME, entry.getEncryptedUsername());
        intent.putExtra(DetailActivity.EXTRA_ENC_PASSWORD, entry.getEncryptedPassword());
        intent.putExtra(DetailActivity.EXTRA_ENC_NOTES, entry.getEncryptedNotes());
        intent.putExtra(DetailActivity.EXTRA_CLOUD_SYNCED, entry.isCloudSynced());
        startActivity(intent);
    }

    /** Bottom sheet (bottom navigation actions) після long-press. */
    private void showEntryActions(PasswordEntry entry) {
        BottomSheetDialog sheet = new BottomSheetDialog(this);
        View content = getLayoutInflater().inflate(R.layout.bottom_sheet_entry_actions, null);
        sheet.setContentView(content);

        TextView title = content.findViewById(R.id.sheet_entry_title);
        title.setText(entry.getServiceName());

        View syncAction = content.findViewById(R.id.sheet_action_sync);
        TextView syncLabel = content.findViewById(R.id.sheet_action_sync_label);
        if (entry.isCloudSynced()) {
            syncLabel.setText(R.string.action_already_synced);
            syncAction.setEnabled(false);
            syncAction.setAlpha(0.5f);
        } else {
            syncLabel.setText(R.string.action_sync_cloud);
            syncAction.setOnClickListener(v -> {
                sheet.dismiss();
                syncEntryToCloud(entry);
            });
        }

        content.findViewById(R.id.sheet_action_open).setOnClickListener(v -> {
            sheet.dismiss();
            openDetail(entry);
        });

        sheet.show();
    }

    private void syncEntryToCloud(PasswordEntry entry) {
        FirebaseUser user = FirebaseManager.getInstance().getCurrentUser();
        if (user == null) {
            Toast.makeText(this, R.string.error_not_signed_in, Toast.LENGTH_LONG).show();
            return;
        }
        FirebaseManager.getInstance().saveEntry(entry, new FirebaseManager.Callback<Void>() {
            @Override
            public void onSuccess(Void result) {
                LocalEntryStore.markCloudSynced(
                        MainActivity.this, user.getUid(), entry.getId(), true);
                Toast.makeText(MainActivity.this, R.string.entry_synced, Toast.LENGTH_SHORT).show();
                refreshLocalList();
            }

            @Override
            public void onError(@NonNull Exception e) {
                Toast.makeText(MainActivity.this,
                        getString(R.string.error_sync, e.getLocalizedMessage()),
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            startActivity(new Intent(this, SettingsActivity.class));
            return true;
        } else if (id == R.id.action_lock) {
            SessionManager.getInstance().lock();
            goToLogin();
            return true;
        } else if (id == R.id.action_sign_out) {
            SessionManager.getInstance().lock();
            FirebaseManager.getInstance().signOut();
            // Локальні записи лишаються прив'язані до uid — не чистимо при sign-out
            goToLogin();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void goToLogin() {
        Intent intent = new Intent(this, LoginActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(intent);
        finish();
    }
}
