package cn.safeagent.biz.common.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * RFC 6238 TOTP（HMAC-SHA1，6 位数字，30s 周期，±1 窗口兼容网络延迟）。
 * 用于 MFA 二次验证。密钥通常以 Base32 下发/存储。
 */
public final class Totp {
    private static final int DIGITS = 6;
    private static final long PERIOD = 30L;
    private static final int WINDOW = 1;

    private Totp() {}

    /** 校验给定 Base32 密钥在窗口中是否匹配 user code（恒定时间比较） */
    public static boolean verify(String secretBase32, String code) {
        if (secretBase32 == null || secretBase32.isBlank()) return false;
        long counter = Instant.now().getEpochSecond() / PERIOD;
        try {
            byte[] key = Base32.decode(secretBase32);
            for (long c = counter - WINDOW; c <= counter + WINDOW; c++) {
                String expected = codeAt(key, c);
                if (MessageDigestHex.equals(expected, code.trim())) return true;
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private static String codeAt(byte[] key, long counter) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] msg = ByteBuffer.allocate(8).putLong(counter).array();
        byte[] hash = mac.doFinal(msg);
        int offset = hash[hash.length - 1] & 0xf;
        int binary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);
        int otp = binary % (int) Math.pow(10, DIGITS);
        return String.format("%0" + DIGITS + "d", otp);
    }

    public static final class Base32 {
        private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        private Base32() {}

        public static byte[] decode(String input) {
            String s = input.toUpperCase().replaceAll("\\s+", "").replace("=", "");
            ByteBuffer buf = ByteBuffer.allocate(s.length() * 5 / 8 + 1);
            int buffer = 0, bitsLeft = 0;
            for (int i = 0; i < s.length(); i++) {
                int value = ALPHABET.indexOf(s.charAt(i));
                if (value < 0) throw new IllegalArgumentException("非法 Base32 字符: " + s.charAt(i));
                buffer = (buffer << 5) | value;
                bitsLeft += 5;
                if (bitsLeft >= 8) {
                    buf.put((byte) ((buffer >> (bitsLeft - 8)) & 0xff));
                    bitsLeft -= 8;
                }
            }
            byte[] out = new byte[buf.position()];
            System.arraycopy(buf.array(), 0, out, 0, buf.position());
            return out;
        }
    }

    private static class MessageDigestHex {
        static boolean equals(String a, String b) {
            return java.security.MessageDigest.isEqual(
                    a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
        }
    }
}