package cn.safeagent.biz.common.util;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HexFormat;

/**
 * 口令散列，与 Python ai_service/auth.py 完全兼容：
 * PBKDF2-SHA256，迭代 200_000，随机 16 字节盐（十六进制）。
 */
public final class PasswordHasher {
    private static final int ITERATIONS = 200_000;
    private static final int KEY_LEN_BITS = 256;
    private static final SecureRandom RAND = new SecureRandom();

    private PasswordHasher() {}

    /** 生成 16 字节十六进制随机盐 */
    public static String randomSaltHex() {
        return HexFormat.of().formatHex(randomBytes(16));
    }

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RAND.nextBytes(b);
        return b;
    }

    /** 计算 PBKDF2-SHA256（十六进制），salt 为 byte[] */
    public static String hash(String password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LEN_BITS);
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return HexFormat.of().formatHex(f.generateSecret(spec).getEncoded());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("PBKDF2 不可用", e);
        }
    }

    /** 生成新盐并计算散列，返回 {hash, saltHex} */
    public static String[] hashNewSalt(String password) {
        byte[] salt = randomBytes(16);
        return new String[]{hash(password, salt), HexFormat.of().formatHex(salt)};
    }

    /** 恒定时间比较十六进制（防时序侧信道） */
    public static boolean constantEquals(String a, String b) {
        return java.security.MessageDigest.isEqual(
                a.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                b.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}