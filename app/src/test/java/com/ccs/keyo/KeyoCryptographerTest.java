package com.ccs.keyo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import com.ccs.keyo.crypto.KeyoCryptographer;

import org.junit.Test;

import javax.crypto.SecretKey;

/** Юніт-тести криптоядра: працюють на JVM без Android-емулятора. */
public class KeyoCryptographerTest {

    @Test
    public void encryptDecryptWithSessionKey_roundTrip() throws Exception {
        char[] password = "correct horse battery staple".toCharArray();
        byte[] salt = KeyoCryptographer.generateSalt();
        SecretKey key = KeyoCryptographer.deriveKey(password, salt);

        String secret = "мій супер-пароль ⚿ 12345";
        String encrypted = KeyoCryptographer.encryptWithKey(secret, key);
        assertNotEquals(secret, encrypted);
        assertEquals(secret, KeyoCryptographer.decryptWithKey(encrypted, key));
    }

    @Test
    public void sameKeySamePlaintext_producesDifferentCiphertexts() throws Exception {
        char[] password = "correct horse battery staple".toCharArray();
        SecretKey key = KeyoCryptographer.deriveKey(password, KeyoCryptographer.generateSalt());

        // Унікальний IV на кожне шифрування → шифротексти не повторюються
        assertNotEquals(
                KeyoCryptographer.encryptWithKey("secret", key),
                KeyoCryptographer.encryptWithKey("secret", key));
    }

    @Test
    public void passwordMode_selfContainedRoundTrip() throws Exception {
        char[] password = "master-password-123!".toCharArray();
        String encrypted = KeyoCryptographer.encrypt("plain data", password.clone());
        assertEquals("plain data",
                KeyoCryptographer.decrypt(encrypted, password.clone()));
    }

    @Test
    public void verifier_acceptsCorrectAndRejectsWrongPassword() throws Exception {
        byte[] salt = KeyoCryptographer.generateSalt();
        SecretKey rightKey = KeyoCryptographer.deriveKey("right-password".toCharArray(), salt);
        SecretKey wrongKey = KeyoCryptographer.deriveKey("wrong-password".toCharArray(), salt);

        String verifier = KeyoCryptographer.createVerifier(rightKey);
        assertTrue(KeyoCryptographer.verifyMasterKey(rightKey, verifier));
        assertFalse(KeyoCryptographer.verifyMasterKey(wrongKey, verifier));
    }

    @Test
    public void tamperedCiphertext_failsAuthentication() throws Exception {
        SecretKey key = KeyoCryptographer.deriveKey(
                "password".toCharArray(), KeyoCryptographer.generateSalt());
        String encrypted = KeyoCryptographer.encryptWithKey("data", key);

        byte[] raw = KeyoCryptographer.decodeBase64(encrypted);
        raw[raw.length - 1] ^= 0x01; // фліп останнього байта GCM-тегу
        String tampered = KeyoCryptographer.encodeBase64(raw);

        assertFalse(KeyoCryptographer.verifyMasterKey(key, tampered));
    }
}
