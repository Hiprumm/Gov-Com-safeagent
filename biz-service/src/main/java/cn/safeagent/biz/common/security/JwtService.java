package cn.safeagent.biz.common.security;

import cn.safeagent.biz.common.config.AppProperties;
import cn.safeagent.biz.common.util.PasswordHasher;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * HS256 JWT，与 Python ai_service/auth.py _issue_jwt / _decode_jwt 逐字节兼容：
 * header{"alg":"HS256","typ":"JWT"}；payload{sub,iat,exp,jti,scope}；
 * 密钥优先读共享 data/jwt_secret.key（实现两服务令牌互认），缺省生成并持久化。
 */
@Service
public class JwtService {
    static final String ALG = "HS256";
    private final byte[] secret;
    private final int ttlSeconds;
    private final ObjectMapper mapper = new ObjectMapper();

    public JwtService(AppProperties props) {
        this.ttlSeconds = props.getJwt().getTtlSeconds() > 0 ? props.getJwt().getTtlSeconds() : 28800;
        byte[] s = loadSecret(props.getJwt().getSecretFile());
        this.secret = s != null ? s : new byte[0];
    }

    private byte[] loadSecret(String secretFile) {
        if (secretFile != null && !secretFile.isBlank()) {
            try {
                Path p = Paths.get(secretFile);
                if (Files.exists(p)) {
                    byte[] data = Files.readAllBytes(p);
                    if (data.length > 0) return data;
                }
            } catch (Exception ignored) {
                // fall through to generate
            }
        }
        byte[] gen = PasswordHasher.randomBytes(32);
        try {
            Path target = secretFile != null && !secretFile.isBlank()
                    ? Paths.get(secretFile)
                    : Paths.get("", "jwt_secret.key");
            Path dir = target.toAbsolutePath().getParent();
            if (dir != null) Files.createDirectories(dir);
            Files.write(target, gen, StandardOpenOption.CREATE_NEW);
        } catch (Exception ignored) {
            // 无法持久化则用临时密钥
        }
        return gen;
    }

    static String b64url(byte[] raw) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    static byte[] b64urlDecode(String seg) {
        return Base64.getUrlDecoder().decode(seg);
    }

    private byte[] hmac(String signingInput) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 不可用", e);
        }
    }

    /** 签发访问令牌，返回 token 字符串 */
    public String createToken(String username) {
        return createToken(username, "access", ttlSeconds);
    }

    /** 签发带 scope / 独立 TTL 的令牌（MFA 票据等） */
    public String createToken(String username, String scope, int ttlSeconds) {
        return createToken(username, scope, ttlSeconds, null, null);
    }

    /**
     * 签发访问令牌，绑定设备指纹(dev)与会话版本(tv)。
     * - deviceFp 非空时写入 dev claim（=请求 User-Agent 的 SHA-256 指纹）；
     * - tokenVersion 非空时写入 tv claim（=该账号当前 token_version）。
     * dev/tv 均为追加 claims，Python `_decode_jwt` 只读 sub/exp/jti/scope，互认不受影响；
     * biz 校验侧对缺失这些 claim 的令牌（Python 签发）放行。
     */
    public String createAccessToken(String username, String deviceFp, Integer tokenVersion) {
        return createToken(username, "access", ttlSeconds, deviceFp, tokenVersion);
    }

    /** 签发带 scope / 独立 TTL / 设备指纹 / 会话版本的令牌 */
    public String createToken(String username, String scope, int ttlSeconds,
                              String deviceFp, Integer tokenVersion) {
        long now = Instant.now().getEpochSecond();
        String jti = HexFormatHex(random16());
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", ALG);
        header.put("typ", "JWT");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub", username);
        payload.put("iat", now);
        payload.put("exp", now + ttlSeconds);
        payload.put("jti", jti);
        payload.put("scope", scope);
        if (deviceFp != null && !deviceFp.isBlank()) {
            payload.put("dev", deviceFp);
        }
        if (tokenVersion != null) {
            payload.put("tv", tokenVersion);
        }

        String headSeg = b64url(serialize(header));
        String paySeg = b64url(serialize(payload));
        String signingInput = headSeg + "." + paySeg;
        String sig = b64url(hmac(signingInput));
        return signingInput + "." + sig;
    }

    /** 设备指纹：User-Agent 的 SHA-256 十六进制（用于令牌跨浏览器/设备绑定） */
    public static String deviceFingerprint(String userAgent) {
        String ua = userAgent == null ? "" : userAgent;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of().formatHex(md.digest(ua.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "";
        }
    }

    /** 校验签名/算法/有效期；合法返回 payload（含 scope, sub, jti），否则 null */
    public Map<String, Object> decode(String token) {
        if (token == null || token.split("\\.", -1).length != 3) return null;
        try {
            String[] parts = token.split("\\.", -1);
            String signingInput = parts[0] + "." + parts[1];
            String expected = b64url(hmac(signingInput));
            if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                    parts[2].getBytes(StandardCharsets.UTF_8))) {
                return null;
            }
            Map<?, ?> header = mapper.readValue(b64urlDecode(parts[0]), Map.class);
            if (!ALG.equals(header.get("alg"))) return null; // 防算法混淆
            Map<String, Object> payload = mapper.readValue(b64urlDecode(parts[1]), Map.class);
            long exp = payload.get("exp") instanceof Number n ? n.longValue() : 0L;
            if (exp > 0 && exp < Instant.now().getEpochSecond()) return null;
            return payload;
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] random16() { return PasswordHasher.randomBytes(16); }
    private static String HexFormatHex(byte[] b) { return java.util.HexFormat.of().formatHex(b); }
    private byte[] serialize(Object o) {
        try { return mapper.writeValueAsBytes(o); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
}