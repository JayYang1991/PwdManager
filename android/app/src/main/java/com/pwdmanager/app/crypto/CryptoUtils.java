package com.pwdmanager.app.crypto;

import android.util.Base64;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {

    public static final String DEFAULT_MASTER_KEY = "PwdManager#MasterSecretKey2026";
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128; // in bits
    private static final int IV_LENGTH = 12; // 12 bytes for GCM
    private static final int SALT_LENGTH = 16; // 16 bytes salt
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH = 256;

    private static SecretKey deriveKey(String masterPassword, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static class EncryptionResult {
        public final String ciphertextBase64;
        public final String ivBase64;
        public final String saltBase64;

        public EncryptionResult(String ciphertextBase64, String ivBase64, String saltBase64) {
            this.ciphertextBase64 = ciphertextBase64;
            this.ivBase64 = ivBase64;
            this.saltBase64 = saltBase64;
        }
    }

    public static EncryptionResult encrypt(String plainText) throws Exception {
        return encrypt(plainText, DEFAULT_MASTER_KEY);
    }

    public static EncryptionResult encrypt(String plainText, String masterPassword) throws Exception {
        if (plainText == null) plainText = "";
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);

        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);

        SecretKey secretKey = deriveKey(masterPassword, salt);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] cipherBytes = cipher.doFinal(plainText.getBytes("UTF-8"));

        String cipherBase64 = Base64.encodeToString(cipherBytes, Base64.NO_WRAP);
        String ivBase64 = Base64.encodeToString(iv, Base64.NO_WRAP);
        String saltBase64 = Base64.encodeToString(salt, Base64.NO_WRAP);

        return new EncryptionResult(cipherBase64, ivBase64, saltBase64);
    }

    public static String decrypt(String ciphertextBase64, String ivBase64, String saltBase64) {
        return decrypt(ciphertextBase64, ivBase64, saltBase64, DEFAULT_MASTER_KEY);
    }

    public static String decrypt(String ciphertextBase64, String ivBase64, String saltBase64, String masterPassword) {
        try {
            if (ciphertextBase64 == null || ciphertextBase64.isEmpty()) return "";
            byte[] cipherBytes = Base64.decode(ciphertextBase64, Base64.NO_WRAP);
            byte[] iv = (ivBase64 != null && !ivBase64.isEmpty()) ? Base64.decode(ivBase64, Base64.NO_WRAP) : new byte[12];
            byte[] salt = (saltBase64 != null && !saltBase64.isEmpty()) ? Base64.decode(saltBase64, Base64.NO_WRAP) : new byte[16];

            SecretKey secretKey = deriveKey(masterPassword, salt);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            byte[] plainBytes = cipher.doFinal(cipherBytes);
            return new String(plainBytes, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
            return "[解密失败]";
        }
    }

    public static EncryptionResult reencrypt(String ciphertextBase64, String ivBase64, String saltBase64, String oldMasterPassword, String newMasterPassword) throws Exception {
        String plain = decrypt(ciphertextBase64, ivBase64, saltBase64, oldMasterPassword);
        if ("[解密失败]".equals(plain)) {
            throw new IllegalArgumentException("无法使用旧密钥解密原数据");
        }
        return encrypt(plain, newMasterPassword);
    }

    public static String generateStrongPassword(int length) {
        String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lower = "abcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        String special = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        String all = upper + lower + digits + special;

        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);

        sb.append(upper.charAt(random.nextInt(upper.length())));
        sb.append(lower.charAt(random.nextInt(lower.length())));
        sb.append(digits.charAt(random.nextInt(digits.length())));
        sb.append(special.charAt(random.nextInt(special.length())));

        for (int i = 4; i < length; i++) {
            sb.append(all.charAt(random.nextInt(all.length())));
        }

        char[] chars = sb.toString().toCharArray();
        for (int i = chars.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char temp = chars[i];
            chars[i] = chars[j];
            chars[j] = temp;
        }

        return new String(chars);
    }
}
