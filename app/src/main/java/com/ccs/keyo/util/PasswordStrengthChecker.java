package com.ccs.keyo.util;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Базова евристична оцінка надійності пароля: 0 (дуже слабкий) … 4 (сильний).
 * Враховує довжину, різноманіття класів символів і чорний список
 * найпоширеніших паролів.
 */
public final class PasswordStrengthChecker {

    public static final int VERY_WEAK = 0;
    public static final int WEAK = 1;
    public static final int FAIR = 2;
    public static final int GOOD = 3;
    public static final int STRONG = 4;

    private static final Set<String> COMMON_PASSWORDS = new HashSet<>(Arrays.asList(
            "password", "123456", "12345678", "123456789", "qwerty", "qwerty123",
            "111111", "abc123", "1234567", "password1", "iloveyou", "admin",
            "welcome", "monkey", "dragon", "letmein", "master", "qazwsx",
            "1q2w3e4r", "zaq12wsx", "пароль", "йцукен"));

    private PasswordStrengthChecker() {
    }

    /** @return оцінка 0..4 */
    public static int score(CharSequence password) {
        if (password == null || password.length() == 0) {
            return VERY_WEAK;
        }
        String lower = password.toString().toLowerCase(Locale.ROOT);
        if (COMMON_PASSWORDS.contains(lower)) {
            return VERY_WEAK;
        }

        int length = password.length();
        boolean hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;
        for (int i = 0; i < length; i++) {
            char c = password.charAt(i);
            if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSymbol = true;
        }
        int classes = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0)
                + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);

        int score = 0;
        if (length >= 8) score++;
        if (length >= 12) score++;
        if (classes >= 3) score++;
        if (classes == 4 || length >= 16) score++;

        // Занадто короткий пароль не може бути сильним незалежно від складу
        if (length < 8) score = Math.min(score, WEAK);
        return Math.min(score, STRONG);
    }

    /** Мінімально прийнятна оцінка для майстер-пароля. */
    public static boolean isAcceptableMasterPassword(CharSequence password) {
        return password != null && password.length() >= 10 && score(password) >= GOOD;
    }
}
