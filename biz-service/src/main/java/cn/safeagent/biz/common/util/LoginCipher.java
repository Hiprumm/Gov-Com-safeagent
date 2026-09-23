package cn.safeagent.biz.common.util;

import cn.safeagent.biz.common.config.AppProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * 登录口令 RSA 传输加密：前端用公钥 RSA-OAEP(SHA-256) 加密口令，此处用私钥解密。
 * 密钥对持久化于 data/login_rsa.key（已随 data/ 被 .gitignore 忽略），首次运行生成。
 * <p>
 * 局限：无 TLS 时主动中间人可替换下发的公钥，本机制防御的是"被动窃听"（口令明文不再裸露于传输链路）；
 * 完整防护仍需生产环境挂 HTTPS。kid 用于让前端/后端确认使用的是同一把公钥（防交错替换）。
 */
@Component
public class LoginCipher {

    private final PrivateKey privateKey;
    private final String kid;

    public LoginCipher(AppProperties props) {
        try {
            String file = props.getSecurity().getLoginRsaFile();
            Path p = (file == null || file.isBlank()) ? Paths.get("", "login_rsa.key") : Paths.get(file);
            this.privateKey = loadOrCreate(p);
            byte[] pk = privateKey.getEncoded();
            this.kid = java.util.HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(pk)).substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("RSA 登录密钥初始化失败", e);
        }
    }

    private PrivateKey loadOrCreate(Path p) throws Exception {
        if (Files.exists(p)) {
            String raw = new String(Files.readAllBytes(p), StandardCharsets.UTF_8).trim();
            byte[] der = Base64.getDecoder().decode(raw);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        }
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        Path dir = p.toAbsolutePath().getParent();
        if (dir != null) Files.createDirectories(dir);
        String b64 = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        try {
            Files.write(p, b64.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE_NEW);
        } catch (Exception ignored) {
            // 无法持久化则使用内存密钥；重启后前端缓存公钥会失配，前端会自动重新拉取
        }
        return kp.getPrivate();
    }

    /** 前端加密用公钥（SPKI PEM，多行） */
    public String getPublicPem() {
        try {
            java.security.interfaces.RSAPrivateCrtKey priv = (java.security.interfaces.RSAPrivateCrtKey) privateKey;
            PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(
                    new java.security.spec.RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));
            String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                    .encodeToString(pub.getEncoded());
            return "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----";
        } catch (Exception e) {
            throw new IllegalStateException("导出 RSA 公钥失败", e);
        }
    }

    public String getKid() { return kid; }

    /** 传入的 kid 是否与当前密钥对一致（防前端用旧公钥加密后无法解密） */
    public boolean kidMatches(String kid) {
        return kid != null && kid.equals(this.kid);
    }

    /** 用私钥 RSA-OAEP(SHA-256) 解密密文，返回明文口令；解密失败返回 null */
    public String decrypt(String encBase64, String kid) {
        if (encBase64 == null || encBase64.isBlank() || !kidMatches(kid)) return null;
        try {
            byte[] raw = Base64.getDecoder().decode(encBase64.trim());
            // 与浏览器 WebCrypto(RSA-OAEP, SHA-256) 对齐：OAEP 与 MGF1 均用 SHA-256（JCA 命名加载默认 MGF1=SHA-1，须显式指定）
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey,
                    new javax.crypto.spec.OAEPParameterSpec("SHA-256", "MGF1",
                            java.security.spec.MGF1ParameterSpec.SHA256, javax.crypto.spec.PSource.PSpecified.DEFAULT));
            return new String(cipher.doFinal(raw), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }
}