package com.ccs.keyo.ui;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.ccs.keyo.R;
import com.ccs.keyo.crypto.KeyoCryptographer;
import com.ccs.keyo.model.PasswordEntry;
import com.ccs.keyo.session.SessionManager;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

/**
 * Адаптер списку записів. Показує назву сервісу та розшифрований логін.
 * Сам пароль у списку НЕ розшифровується — лише на екрані деталей.
 */
public class PasswordEntryAdapter
        extends RecyclerView.Adapter<PasswordEntryAdapter.EntryViewHolder> {

    public interface OnEntryClickListener {
        void onEntryClick(PasswordEntry entry);
    }

    private final List<PasswordEntry> entries = new ArrayList<>();
    private final OnEntryClickListener clickListener;

    public PasswordEntryAdapter(OnEntryClickListener clickListener) {
        this.clickListener = clickListener;
    }

    public void submit(List<PasswordEntry> newEntries) {
        entries.clear();
        entries.addAll(newEntries);
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public EntryViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_password_entry, parent, false);
        return new EntryViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull EntryViewHolder holder, int position) {
        PasswordEntry entry = entries.get(position);
        holder.serviceName.setText(entry.getServiceName());
        holder.username.setText(decryptPreview(entry.getEncryptedUsername(), holder));
        holder.itemView.setOnClickListener(v -> clickListener.onEntryClick(entry));
    }

    @Override
    public int getItemCount() {
        return entries.size();
    }

    /** Розшифрування логіна для прев'ю; при заблокованій сесії — заглушка. */
    private String decryptPreview(String encrypted, EntryViewHolder holder) {
        if (encrypted == null || encrypted.isEmpty()) {
            return "";
        }
        SecretKey key = SessionManager.getInstance().getMasterKey();
        if (key == null) {
            return holder.itemView.getContext().getString(R.string.locked_placeholder);
        }
        try {
            return KeyoCryptographer.decryptWithKey(encrypted, key);
        } catch (Exception e) {
            return holder.itemView.getContext().getString(R.string.decrypt_error_placeholder);
        }
    }

    static class EntryViewHolder extends RecyclerView.ViewHolder {
        final TextView serviceName;
        final TextView username;

        EntryViewHolder(@NonNull View itemView) {
            super(itemView);
            serviceName = itemView.findViewById(R.id.item_service_name);
            username = itemView.findViewById(R.id.item_username);
        }
    }
}
