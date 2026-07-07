package com.ccs.keyo.crypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Криптографічне ядро Keyo. Архітектура Zero-Knowledge:
 *
 *  1. Майстер-пароль існує ЛИШЕ в пам'яті пристрою (char[]) і ніколи не
 *     передається на сервер, не логовується та не зберігається на диску.
 *  2. З майстер-пароля через Argon2id (memory-hard KDF) виводиться
 *     256-бітний симетричний ключ. Сіль — випадкова, унікальна для користувача.
 *  3. Дані шифруються AES-256-GCM (автентифіковане шифрування) з унікальним
 *     12-байтовим IV для КОЖНОЇ операції шифрування. Повторне використання IV
 *     з тим самим ключем у GCM катастрофічне, тому IV завжди від SecureRandom.
 *  4. У Firestore потрапляють лише: сіль, параметри KDF, IV та шифротекст.
 *     Жоден із цих артефактів не дозволяє відновити пароль чи ключ.
 *
 * Argon2id реалізовано Bouncy Castle на чистій Java — NDK не потрібен.
 * Провайдер BC глобально не реєструється (використовуємо low-level API),
 * тому конфлікту з урізаним системним "BC" на Android немає.
 */
public final class KeyoCryptographer {

    // ---- Параметри KDF (Argon2id) ----
    // Зберігаються у профілі сховища, тож їх можна посилювати у майбутніх
    // версіях без ламання старих даних.
    public static final int KDF_MEMORY_KIB = 32768; // 32 MiB
    public static final int KDF_ITERATIONS = 3;
    public static final int KDF_PARALLELISM = 1;
    public static final int SALT_LENGTH_BYTES = 16;
    public static final int KEY_LENGTH_BYTES = 32;  // AES-256

    // ---- Параметри шифру (AES-256-GCM) ----
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;    // рекомендовано для GCM
    private static final int GCM_TAG_LENGTH_BITS = 128;

    // Версії формату шифротексту (перший байт пакета):
    // v1 — [ver][iv][ct] — шифрування вже виведеним сесійним ключем.
    // v2 — [ver][salt][iv][ct] — самодостатній пакет: сіль вбудована,
    //      ключ виводиться з майстер-пароля при кожному виклику (повільно!).
    private static final byte VERSION_KEY_MODE = 0x01;
    private static final byte VERSION_PASSWORD_MODE = 0x02;

    // Константа для верифікації майстер-пароля без його зберігання:
    // шифруємо відомий рядок і кладемо результат у профіль. Якщо при вході
    // розшифрування вдалось (GCM-тег зійшовся) — пароль правильний.
    private static final String VERIFIER_PLAINTEXT = "keyo.master.verifier.v1";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private KeyoCryptographer() {
    }

    // =====================================================================
    // Деривація ключа (Argon2id)
    // =====================================================================

    /** Генерує криптографічно стійку випадкову сіль для KDF. */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Виводить AES-256 ключ із майстер-пароля. Операція навмисно повільна та
     * memory-hard (захист від GPU/ASIC-перебору) — викликати у фоновому потоці.
     * Проміжний байтовий буфер пароля затирається одразу після використання.
     */
    public static SecretKey deriveKey(char[] masterPassword, byte[] salt,
                                      int memoryKib, int iterations, int parallelism) {
        byte[] passwordBytes = charsToUtf8Bytes(masterPassword);
        byte[] keyBytes = new byte[KEY_LENGTH_BYTES];
        try {
            Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withSalt(salt)
                    .withMemoryAsKB(memoryKib)
                    .withIterations(iterations)
                    .withParallelism(parallelism)
                    .build();
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(params);
            generator.generateBytes(passwordBytes, keyBytes);
            // SecretKeySpec копіює масив, тож локальну копію нижче затираємо.
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            wipe(passwordBytes);
            wipe(keyBytes);
        }
    }

    /** Деривація з параметрами за замовчуванням. */
    public static SecretKey deriveKey(char[] masterPassword, byte[] salt) {
        return deriveKey(masterPassword, salt, KDF_MEMORY_KIB, KDF_ITERATIONS, KDF_PARALLELISM);
    }

    // =====================================================================
    // Шифрування сесійним ключем (основний шлях додатка)
    // =====================================================================
    // Argon2 виконується ОДИН раз при розблокуванні; далі всі записи
    // шифруються/розшифровуються швидким AES-GCM цим ключем.

    /** Шифрує рядок сесійним ключем. Повертає Base64([v1][iv][ciphertext+tag]). */
    public static String encryptWithKey(String plainText, SecretKey key)
            throws GeneralSecurityException {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(iv); // унікальний IV для кожного шифрування

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        ByteBuffer packet = ByteBuffer.allocate(1 + iv.length + cipherText.length);
        packet.put(VERSION_KEY_MODE).put(iv).put(cipherText);
        return Base64.getEncoder().encodeToString(packet.array());
    }

    /** Розшифровує пакет формату v1. GCM автентифікує дані: підміна → виняток. */
    public static String decryptWithKey(String encoded, SecretKey key)
            throws GeneralSecurityException {
        ByteBuffer packet = ByteBuffer.wrap(Base64.getDecoder().decode(encoded));
        byte version = packet.get();
        if (version != VERSION_KEY_MODE) {
            throw new GeneralSecurityException("Невідома версія пакета: " + version);
        }
        byte[] iv = new byte[IV_LENGTH_BYTES];
        packet.get(iv);
        byte[] cipherText = new byte[packet.remaining()];
        packet.get(cipherText);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
    }

    // =====================================================================
    // Самодостатній режим encrypt/decrypt(майстер-пароль)
    // =====================================================================
    // Зручні методи згідно з ТЗ. Кожен виклик виконує повний Argon2id,
    // тому для масових операцій використовуйте сесійний ключ вище.

    /**
     * Шифрує рядок безпосередньо майстер-паролем. Генерує свіжу сіль та IV,
     * вбудовує їх у пакет: Base64([v2][salt][iv][ciphertext+tag]).
     */
    public static String encrypt(String plainText, char[] masterPassword)
            throws GeneralSecurityException {
        byte[] salt = generateSalt();
        SecretKey key = deriveKey(masterPassword, salt);
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            ByteBuffer packet = ByteBuffer.allocate(1 + salt.length + iv.length + cipherText.length);
            packet.put(VERSION_PASSWORD_MODE).put(salt).put(iv).put(cipherText);
            return Base64.getEncoder().encodeToString(packet.array());
        } finally {
            destroyKey(key);
        }
    }

    /** Розшифровує пакет формату v2, виводячи ключ із вбудованої солі. */
    public static String decrypt(String cipherTextEncoded, char[] masterPassword)
            throws GeneralSecurityException {
        ByteBuffer packet = ByteBuffer.wrap(Base64.getDecoder().decode(cipherTextEncoded));
        byte version = packet.get();
        if (version != VERSION_PASSWORD_MODE) {
            throw new GeneralSecurityException("Невідома версія пакета: " + version);
        }
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        packet.get(salt);
        byte[] iv = new byte[IV_LENGTH_BYTES];
        packet.get(iv);
        byte[] cipherText = new byte[packet.remaining()];
        packet.get(cipherText);

        SecretKey key = deriveKey(masterPassword, salt);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
        } finally {
            destroyKey(key);
        }
    }

    // =====================================================================
    // Верифікатор майстер-пароля
    // =====================================================================

    /**
     * Створює верифікатор: шифрує відому константу виведеним ключем.
     * Зберігається у профілі (локально + Firestore) і дозволяє перевірити
     * правильність майстер-пароля, НЕ зберігаючи ані пароль, ані його хеш.
     */
    public static String createVerifier(SecretKey masterKey) throws GeneralSecurityException {
        return encryptWithKey(VERIFIER_PLAINTEXT, masterKey);
    }

    /** true, якщо ключ (а отже і майстер-пароль) правильний. */
    public static boolean verifyMasterKey(SecretKey masterKey, String verifier) {
        try {
            return VERIFIER_PLAINTEXT.equals(decryptWithKey(verifier, masterKey));
        } catch (GeneralSecurityException e) {
            // GCM-тег не зійшовся → неправильний пароль
            return false;
        }
    }

    // =====================================================================
    // Утиліти
    // =====================================================================

    /** Генератор випадкових паролів для нових записів. */
    public static String generatePassword(int length) {
        final String alphabet =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(alphabet.charAt(SECURE_RANDOM.nextInt(alphabet.length())));
        }
        return sb.toString();
    }

    /**
     * char[] → UTF-8 byte[] без створення проміжного String:
     * String є immutable і живе в купі до GC, тож його неможливо затерти.
     */
    private static byte[] charsToUtf8Bytes(char[] chars) {
        CharBuffer charBuffer = CharBuffer.wrap(chars);
        ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
        byte[] bytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(bytes);
        // Затираємо внутрішній буфер енкодера
        if (byteBuffer.hasArray()) {
            wipe(byteBuffer.array());
        }
        return bytes;
    }

    /** Затирання чутливих масивів у пам'яті (best-effort у межах JVM). */
    public static void wipe(byte[] data) {
        if (data != null) Arrays.fill(data, (byte) 0);
    }

    public static void wipe(char[] data) {
        if (data != null) Arrays.fill(data, '\0');
    }

    /** Best-effort знищення ключа: SecretKeySpec не підтримує destroy() на Android. */
    private static void destroyKey(SecretKey key) {
        try {
            key.destroy();
        } catch (Exception ignored) {
            // SecretKeySpec кидає DestroyFailedException — копія ключа
            // залишиться до GC; це відома межа JCA на Java/Android.
        }
    }

    public static String encodeBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] decodeBase64(String data) {
        return Base64.getDecoder().decode(data);
    }
}
