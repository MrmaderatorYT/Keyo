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
import com.ccs.keyo.util.LocalVaultStore;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.firebase.firestore.ListenerRegistration;

import java.util.List;

/**
 * Список збережених паролів. Записи приходять із Firestore зашифрованими
 * та розшифровуються адаптером на льоту сесійним ключем із пам'яті.
 */
public class MainActivity extends BaseSecureActivity {

    private PasswordEntryAdapter adapter;
    private TextView emptyView;
    private ListenerRegistration entriesRegistration;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar toolbar = findViewById(R.id.main_toolbar);
        setSupportActionBar(toolbar);

        emptyView = findViewById(R.id.main_empty_view);
        RecyclerView recyclerView = findViewById(R.id.main_recycler);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));
        adapter = new PasswordEntryAdapter(entry -> {
            Intent intent = new Intent(this, DetailActivity.class);
            intent.putExtra(DetailActivity.EXTRA_ENTRY_ID, entry.getId());
            intent.putExtra(DetailActivity.EXTRA_SERVICE_NAME, entry.getServiceName());
            intent.putExtra(DetailActivity.EXTRA_ENC_USERNAME, entry.getEncryptedUsername());
            intent.putExtra(DetailActivity.EXTRA_ENC_PASSWORD, entry.getEncryptedPassword());
            intent.putExtra(DetailActivity.EXTRA_ENC_NOTES, entry.getEncryptedNotes());
            startActivity(intent);
        });
        recyclerView.setAdapter(adapter);

        FloatingActionButton fab = findViewById(R.id.main_fab_add);
        fab.setOnClickListener(v ->
                startActivity(new Intent(this, DetailActivity.class)));
    }

    @Override
    protected void onStart() {
        super.onStart();
        // Realtime-синхронізація: будь-яка зміна у Firestore одразу в списку
        entriesRegistration = FirebaseManager.getInstance().listenEntries(
                new FirebaseManager.Callback<List<PasswordEntry>>() {
                    @Override
                    public void onSuccess(List<PasswordEntry> entries) {
                        adapter.submit(entries);
                        emptyView.setVisibility(
                                entries.isEmpty() ? View.VISIBLE : View.GONE);
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
    protected void onStop() {
        if (entriesRegistration != null) {
            entriesRegistration.remove();
            entriesRegistration = null;
        }
        super.onStop();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_lock) {
            // Ручне блокування: ключ затирається, повернення на екран входу
            SessionManager.getInstance().lock();
            goToLogin();
            return true;
        } else if (id == R.id.action_sign_out) {
            SessionManager.getInstance().lock();
            FirebaseManager.getInstance().signOut();
            LocalVaultStore.clear(this);
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
