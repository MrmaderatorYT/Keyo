package com.ccs.keyo.model;

import com.google.firebase.firestore.DocumentId;
import com.google.firebase.firestore.Exclude;
import com.google.firebase.firestore.ServerTimestamp;

import java.util.Date;

/**
 * Запис пароля: локальне сховище (за замовчуванням) та/або Firestore.
 *
 * Zero-Knowledge: поля encryptedUsername / encryptedPassword / encryptedNotes
 * містять Base64-пакети формату [version][IV][ciphertext+GCM-tag] —
 * IV вбудований у пакет, тож окреме поле не потрібне. Сіль KDF одна на
 * користувача і зберігається у профілі сховища (VaultProfile), а не в кожному
 * записі: Argon2 виконується один раз при розблокуванні, а не на кожен запис.
 *
 * Сервер бачить лише назву сервісу (для сортування списку) та шифротексти,
 * які без майстер-пароля розшифрувати неможливо.
 *
 * cloudSynced — лише локальний прапор (не пишеться у Firestore).
 */
public class PasswordEntry {

    @DocumentId
    private String id;

    private String serviceName;        // назва сервісу (відкрито, для списку/пошуку)
    private String encryptedUsername;  // логін — зашифровано AES-256-GCM
    private String encryptedPassword;  // пароль — зашифровано AES-256-GCM
    private String encryptedNotes;     // нотатки — зашифровано AES-256-GCM

    @ServerTimestamp
    private Date createdAt;
    @ServerTimestamp
    private Date updatedAt;

    /** Чи є копія цього запису у Firestore. Не серіалізується на сервер. */
    @Exclude
    private boolean cloudSynced;

    /** Порожній конструктор обов'язковий для десеріалізації Firestore. */
    public PasswordEntry() {
    }

    public PasswordEntry(String serviceName, String encryptedUsername,
                         String encryptedPassword, String encryptedNotes) {
        this.serviceName = serviceName;
        this.encryptedUsername = encryptedUsername;
        this.encryptedPassword = encryptedPassword;
        this.encryptedNotes = encryptedNotes;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getEncryptedUsername() {
        return encryptedUsername;
    }

    public void setEncryptedUsername(String encryptedUsername) {
        this.encryptedUsername = encryptedUsername;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }

    public String getEncryptedNotes() {
        return encryptedNotes;
    }

    public void setEncryptedNotes(String encryptedNotes) {
        this.encryptedNotes = encryptedNotes;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    public Date getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Date updatedAt) {
        this.updatedAt = updatedAt;
    }

    @Exclude
    public boolean isCloudSynced() {
        return cloudSynced;
    }

    public void setCloudSynced(boolean cloudSynced) {
        this.cloudSynced = cloudSynced;
    }
}

