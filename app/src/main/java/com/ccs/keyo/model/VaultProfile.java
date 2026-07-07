package com.ccs.keyo.model;

/**
 * Профіль сховища користувача — документ users/{uid} у Firestore
 * (дублюється локально для офлайн-розблокування).
 *
 * Містить лише НЕсекретні криптографічні артефакти:
 *  - kdfSalt: сіль Argon2id (публічна за визначенням KDF);
 *  - kdfMemoryKib / kdfIterations / kdfParallelism: параметри KDF,
 *    збережені явно, щоб їх можна було посилювати в нових версіях;
 *  - verifier: AES-GCM-шифротекст відомої константи — дозволяє перевірити
 *    майстер-пароль на пристрої, не зберігаючи ані пароль, ані його хеш.
 *
 * Знання всіх цих полів НЕ дає можливості відновити майстер-пароль
 * інакше, ніж повним перебором проти Argon2id.
 */
public class VaultProfile {

    private String kdfSalt;      // Base64
    private int kdfMemoryKib;
    private int kdfIterations;
    private int kdfParallelism;
    private String verifier;     // Base64-пакет AES-GCM
    private long createdAt;

    /** Порожній конструктор обов'язковий для десеріалізації Firestore. */
    public VaultProfile() {
    }

    public VaultProfile(String kdfSalt, int kdfMemoryKib, int kdfIterations,
                        int kdfParallelism, String verifier, long createdAt) {
        this.kdfSalt = kdfSalt;
        this.kdfMemoryKib = kdfMemoryKib;
        this.kdfIterations = kdfIterations;
        this.kdfParallelism = kdfParallelism;
        this.verifier = verifier;
        this.createdAt = createdAt;
    }

    public String getKdfSalt() {
        return kdfSalt;
    }

    public void setKdfSalt(String kdfSalt) {
        this.kdfSalt = kdfSalt;
    }

    public int getKdfMemoryKib() {
        return kdfMemoryKib;
    }

    public void setKdfMemoryKib(int kdfMemoryKib) {
        this.kdfMemoryKib = kdfMemoryKib;
    }

    public int getKdfIterations() {
        return kdfIterations;
    }

    public void setKdfIterations(int kdfIterations) {
        this.kdfIterations = kdfIterations;
    }

    public int getKdfParallelism() {
        return kdfParallelism;
    }

    public void setKdfParallelism(int kdfParallelism) {
        this.kdfParallelism = kdfParallelism;
    }

    public String getVerifier() {
        return verifier;
    }

    public void setVerifier(String verifier) {
        this.verifier = verifier;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }
}
