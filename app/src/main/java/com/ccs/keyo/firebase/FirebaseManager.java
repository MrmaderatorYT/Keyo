package com.ccs.keyo.firebase;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.ccs.keyo.model.PasswordEntry;
import com.ccs.keyo.model.VaultProfile;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.FirebaseFirestoreException;
import com.google.firebase.firestore.ListenerRegistration;
import com.google.firebase.firestore.Query;
import com.google.firebase.firestore.QueryDocumentSnapshot;
import com.google.firebase.firestore.QuerySnapshot;
import com.google.firebase.firestore.WriteBatch;

import java.util.ArrayList;
import java.util.List;

/**
 * Єдина точка взаємодії з Firebase.
 *
 * Zero-Knowledge розмежування відповідальностей:
 *  - Firebase Auth автентифікує ОБЛІКОВИЙ ЗАПИС (email + пароль акаунта).
 *    Пароль акаунта ≠ майстер-пароль! Майстер-пароль ніколи не потрапляє
 *    до цього класу і ніколи не залишає пристрій.
 *  - Firestore зберігає лише шифротексти та публічні KDF-артефакти.
 *    Усе шифрування виконується ДО виклику цього класу (KeyoCryptographer),
 *    усе розшифрування — ПІСЛЯ отримання даних, на пристрої.
 *
 * Структура Firestore:
 *   users/{uid}                — VaultProfile (сіль, параметри KDF, верифікатор)
 *   users/{uid}/entries/{id}   — PasswordEntry (шифротексти)
 */
public final class FirebaseManager {

    /** Універсальний колбек для асинхронних операцій. */
    public interface Callback<T> {
        void onSuccess(T result);

        void onError(@NonNull Exception e);
    }

    private static final String COLLECTION_USERS = "users";
    private static final String COLLECTION_ENTRIES = "entries";
    private static final String FIELD_SERVICE_NAME = "serviceName";

    private static FirebaseManager instance;
    private static boolean firebaseAvailable = true;

    private final FirebaseAuth auth;
    private final FirebaseFirestore firestore;

    private FirebaseManager() {
        FirebaseAuth authTmp = null;
        FirebaseFirestore firestoreTmp = null;
        try {
            authTmp = FirebaseAuth.getInstance();
            firestoreTmp = FirebaseFirestore.getInstance();
            firebaseAvailable = true;
        } catch (IllegalStateException e) {
            firebaseAvailable = false;
        }
        auth = authTmp;
        firestore = firestoreTmp;
    }

    public static synchronized FirebaseManager getInstance() {
        if (instance == null) {
            instance = new FirebaseManager();
        }
        return instance;
    }

    /** @return true, якщо Firebase ініціалізовано і готовий до роботи. */
    public static boolean isAvailable() {
        getInstance(); // гарантує ініціалізацію instance
        return firebaseAvailable;
    }

    // =====================================================================
    // Автентифікація акаунта (НЕ майстер-пароля)
    // =====================================================================

    @Nullable
    public FirebaseUser getCurrentUser() {
        if (!firebaseAvailable || auth == null) {
            return null;
        }
        return auth.getCurrentUser();
    }

    public void register(@NonNull String email, @NonNull String accountPassword,
                         @NonNull Callback<FirebaseUser> callback) {
        if (!firebaseAvailable || auth == null) {
            callback.onError(new IllegalStateException(
                    "Firebase не ініціалізовано. Див. README-KEYO.md"));
            return;
        }
        auth.createUserWithEmailAndPassword(email, accountPassword)
                .addOnSuccessListener(result -> callback.onSuccess(result.getUser()))
                .addOnFailureListener(callback::onError);
    }

    public void signIn(@NonNull String email, @NonNull String accountPassword,
                       @NonNull Callback<FirebaseUser> callback) {
        if (!firebaseAvailable || auth == null) {
            callback.onError(new IllegalStateException(
                    "Firebase не ініціалізовано. Див. README-KEYO.md"));
            return;
        }
        auth.signInWithEmailAndPassword(email, accountPassword)
                .addOnSuccessListener(result -> callback.onSuccess(result.getUser()))
                .addOnFailureListener(callback::onError);
    }

    public void signOut() {
        if (firebaseAvailable && auth != null) {
            auth.signOut();
        }
    }

    // =====================================================================
    // Профіль сховища (сіль + параметри KDF + верифікатор)
    // =====================================================================

    public void saveVaultProfile(@NonNull VaultProfile profile,
                                 @NonNull Callback<Void> callback) {
        if (!firebaseAvailable || firestore == null) {
            callback.onError(new IllegalStateException(
                    "Firebase не ініціалізовано. Див. README-KEYO.md"));
            return;
        }
        String uid = requireUid(callback);
        if (uid == null) return;
        firestore.collection(COLLECTION_USERS).document(uid)
                .set(profile)
                .addOnSuccessListener(callback::onSuccess)
                .addOnFailureListener(callback::onError);
    }

    /** Повертає профіль або null, якщо сховище ще не створено на цьому акаунті. */
    public void fetchVaultProfile(@NonNull Callback<VaultProfile> callback) {
        if (!firebaseAvailable || firestore == null) {
            callback.onError(new IllegalStateException(
                    "Firebase не ініціалізовано. Див. README-KEYO.md"));
            return;
        }
        String uid = requireUid(callback);
        if (uid == null) return;
        firestore.collection(COLLECTION_USERS).document(uid)
                .get()
                .addOnSuccessListener((DocumentSnapshot snapshot) ->
                        callback.onSuccess(snapshot.exists()
                                ? snapshot.toObject(VaultProfile.class)
                                : null))
                .addOnFailureListener(callback::onError);
    }

    // =====================================================================
    // CRUD записів (сюди потрапляють ЛИШЕ шифротексти)
    // =====================================================================

    /**
     * Зберігає запис у Firestore за клієнтським id (завжди document(id).set).
     * id має бути заданий локально (UUID), щоб локальна й хмарна копії збігались.
     */
    public void saveEntry(@NonNull PasswordEntry entry, @NonNull Callback<Void> callback) {
        if (!firebaseAvailable || firestore == null) {
            callback.onError(new IllegalStateException(
                    "Firebase не ініціалізовано. Див. README-KEYO.md"));
            return;
        }
        String uid = requireUid(callback);
        if (uid == null) return;
        if (entry.getId() == null || entry.getId().isEmpty()) {
            callback.onError(new IllegalArgumentException(
                    "Entry id is required before cloud save"));
            return;
        }
        firestore.collection(COLLECTION_USERS).document(uid)
                .collection(COLLECTION_ENTRIES).document(entry.getId())
                .set(entry)
                .addOnSuccessListener(callback::onSuccess)
                .addOnFailureListener(callback::onError);
    }

    public void deleteEntry(@NonNull String entryId, @NonNull Callback<Void> callback) {
        if (!firebaseAvailable || firestore == null) {
            callback.onError(new IllegalStateException(
                    "Firebase не ініціалізовано. Див. README-KEYO.md"));
            return;
        }
        String uid = requireUid(callback);
        if (uid == null) return;
        firestore.collection(COLLECTION_USERS).document(uid)
                .collection(COLLECTION_ENTRIES).document(entryId)
                .delete()
                .addOnSuccessListener(callback::onSuccess)
                .addOnFailureListener(callback::onError);
    }

    /** Одноразове завантаження всіх записів із Firestore (для merge у локальне сховище). */
    public void fetchEntries(@NonNull Callback<List<PasswordEntry>> callback) {
        if (!firebaseAvailable || firestore == null) {
            callback.onError(new IllegalStateException(
                    "Firebase не ініціалізовано. Див. README-KEYO.md"));
            return;
        }
        String uid = requireUid(callback);
        if (uid == null) return;
        firestore.collection(COLLECTION_USERS).document(uid)
                .collection(COLLECTION_ENTRIES)
                .orderBy(FIELD_SERVICE_NAME, Query.Direction.ASCENDING)
                .get()
                .addOnSuccessListener((QuerySnapshot snapshots) -> {
                    List<PasswordEntry> entries = new ArrayList<>();
                    for (QueryDocumentSnapshot doc : snapshots) {
                        entries.add(doc.toObject(PasswordEntry.class));
                    }
                    callback.onSuccess(entries);
                })
                .addOnFailureListener(callback::onError);
    }

    /**
     * Realtime-підписка на список записів (миттєва синхронізація між
     * пристроями). Дані приходять зашифрованими; розшифрування — справа UI.
     * Обов'язково викликати remove() на реєстрації в onStop()/onDestroy().
     */
    @Nullable
    public ListenerRegistration listenEntries(@NonNull Callback<List<PasswordEntry>> callback) {
        if (!firebaseAvailable || firestore == null) {
            callback.onError(new IllegalStateException(
                    "Firebase не ініціалізовано. Див. README-KEYO.md"));
            return null;
        }
        String uid = requireUid(callback);
        if (uid == null) return null;
        return firestore.collection(COLLECTION_USERS).document(uid)
                .collection(COLLECTION_ENTRIES)
                .orderBy(FIELD_SERVICE_NAME, Query.Direction.ASCENDING)
                .addSnapshotListener((QuerySnapshot snapshots, FirebaseFirestoreException e) -> {
                    if (e != null) {
                        callback.onError(e);
                        return;
                    }
                    List<PasswordEntry> entries = new ArrayList<>();
                    if (snapshots != null) {
                        for (QueryDocumentSnapshot doc : snapshots) {
                            entries.add(doc.toObject(PasswordEntry.class));
                        }
                    }
                    callback.onSuccess(entries);
                });
    }

    /**
     * Видаляє всі записи користувача з Firestore (профіль vault лишається).
     * Акаунт Auth не чіпається.
     */
    public void deleteAllCloudEntries(@NonNull Callback<Void> callback) {
        if (!firebaseAvailable || firestore == null) {
            callback.onError(new IllegalStateException(
                    "Firebase не ініціалізовано. Див. README-KEYO.md"));
            return;
        }
        String uid = requireUid(callback);
        if (uid == null) return;
        firestore.collection(COLLECTION_USERS).document(uid)
                .collection(COLLECTION_ENTRIES)
                .get()
                .addOnSuccessListener(snapshots -> {
                    if (snapshots.isEmpty()) {
                        callback.onSuccess(null);
                        return;
                    }
                    WriteBatch batch = firestore.batch();
                    int count = 0;
                    // Firestore batch limit = 500
                    List<Task<Void>> commits = new ArrayList<>();
                    for (DocumentSnapshot doc : snapshots.getDocuments()) {
                        batch.delete(doc.getReference());
                        count++;
                        if (count >= 450) {
                            commits.add(batch.commit());
                            batch = firestore.batch();
                            count = 0;
                        }
                    }
                    if (count > 0) {
                        commits.add(batch.commit());
                    }
                    if (commits.isEmpty()) {
                        callback.onSuccess(null);
                        return;
                    }
                    Tasks.whenAll(commits)
                            .addOnSuccessListener(v -> callback.onSuccess(null))
                            .addOnFailureListener(callback::onError);
                })
                .addOnFailureListener(callback::onError);
    }

    /**
     * Повне видалення акаунта: усі entries + документ users/{uid} + Firebase Auth user.
     * Може вимагати недавнього re-auth (Firebase Auth).
     */
    public void deleteAccount(@NonNull Callback<Void> callback) {
        if (!firebaseAvailable || firestore == null || auth == null) {
            callback.onError(new IllegalStateException(
                    "Firebase не ініціалізовано. Див. README-KEYO.md"));
            return;
        }
        FirebaseUser user = auth.getCurrentUser();
        if (user == null) {
            callback.onError(new IllegalStateException(
                    "Користувач не автентифікований у Firebase"));
            return;
        }
        String uid = user.getUid();
        deleteAllCloudEntries(new Callback<Void>() {
            @Override
            public void onSuccess(Void result) {
                firestore.collection(COLLECTION_USERS).document(uid)
                        .delete()
                        .addOnCompleteListener(profileTask ->
                                user.delete()
                                        .addOnSuccessListener(v -> callback.onSuccess(null))
                                        .addOnFailureListener(callback::onError));
            }

            @Override
            public void onError(@NonNull Exception e) {
                callback.onError(e);
            }
        });
    }

    /** uid поточного користувача або помилка в колбек, якщо не автентифіковано. */
    @Nullable
    private String requireUid(@NonNull Callback<?> callback) {
        if (!firebaseAvailable || auth == null) {
            callback.onError(new IllegalStateException(
                    "Firebase не ініціалізовано. Див. README-KEYO.md"));
            return null;
        }
        FirebaseUser user = auth.getCurrentUser();
        if (user == null) {
            callback.onError(new IllegalStateException(
                    "Користувач не автентифікований у Firebase"));
            return null;
        }
        return user.getUid();
    }
}

