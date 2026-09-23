package cn.safeagent.biz.auth;

import cn.safeagent.biz.common.config.AppProperties;
import cn.safeagent.biz.common.security.JwtService;
import cn.safeagent.biz.common.util.PasswordHasher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 认证服务：口令校验（PBKDF2，与 Python 兼容）、连续失败锁定、JWT 签发、MFA 票据。
 * 登录失败计数为进程内状态（与 Python 默认一致；多副本部署建议迁共享存储）。
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private static final List<String> ROLES = List.of("admin", "operator", "auditor", "manager", "user");

    /** 强制 MFA 的角色（seed 时写 force_mfa=1） */
    private static final List<String> FORCE_MFA_ROLES = List.of("admin", "operator", "auditor");

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String[] DEMO = {
            // username, display_name, role, department, position
            "admin:系统管理员:admin:信息化与网络安全处:安全管理员",
            "operator:安全运维员:operator:信息化与网络安全处:安全运维",
            "auditor:合规审计员:auditor:法务与合规部:合规审计",
            "user:业务用户:user:综合办公室:业务经办",
    };

    private final UserRepository users;
    private final JwtService jwt;
    private final int maxLoginFails;
    private final long lockSeconds;
    // username -> {count, lockUntilEpochMillis}
    private final Map<String, int[]> loginFails = new ConcurrentHashMap<>();
    private final Map<String, long[]> lockUntil = new ConcurrentHashMap<>();

    public AuthService(UserRepository users, JwtService jwt, AppProperties props) {
        this.users = users;
        this.jwt = jwt;
        this.maxLoginFails = props.getJwt().getMaxLoginFails() > 0 ? props.getJwt().getMaxLoginFails() : 5;
        this.lockSeconds = props.getJwt().getLoginLockSeconds() > 0 ? props.getJwt().getLoginLockSeconds() : 300L;
        users.ensureTokenVersionColumn(); // 存量库迁移：补充 token_version 列（幂等）
        users.ensureForceMfaColumn();     // 存量库迁移：补充 force_mfa 列（幂等，与 Python 侧对齐）
        seedIfEmpty();
    }

    /** 生产模式判定：SAFEAGENT_ENV=production（未设置或其它值视为演示模式） */
    public static boolean isProductionEnv() {
        return "production".equalsIgnoreCase(System.getenv("SAFEAGENT_ENV"));
    }

    private void seedIfEmpty() {
        if (users.countUsers() > 0) return;
        boolean production = isProductionEnv();
        StringBuilder creds = new StringBuilder();
        for (String line : DEMO) {
            String[] p = line.split(":");
            // 生产模式：每账号独立随机口令（绝不使用 admin123）；演示模式保留固定口令
            String password = production ? randomPassword() : "admin123";
            String[] hs = PasswordHasher.hashNewSalt(password);
            users.upsertUser(p[0], hs[0], hs[1], p[1], p[2], p[3], p[4], "active", "");
            users.markForceMfa(p[0], FORCE_MFA_ROLES.contains(p[2]));
            if (production) {
                creds.append(p[0]).append(':').append(password).append(System.lineSeparator());
            }
        }
        if (production) {
            String file = writeInitialCredentials(creds.toString());
            // 只提示文件位置，不在日志回显口令本体
            log.warn("【生产模式】首次启动已为初始账号生成随机口令并写入 {}，请立即妥善保管并限制访问权限", file);
        } else {
            log.warn(">>> 安全警告：演示口令 admin123 仅限开发环境使用，生产部署必须设置 SAFEAGENT_ENV=production <<<");
        }
    }

    /** 生成 22 字符 URL-safe Base64 随机口令（16 字节 SecureRandom 熵） */
    private static String randomPassword() {
        byte[] buf = new byte[16];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf); // 16 字节 -> 22 字符
    }

    /** 初始凭据文件路径：环境变量 SAFEAGENT_CREDENTIALS_FILE，默认 data/initial_credentials.txt（相对工作目录） */
    private static String credentialsFilePath() {
        String p = System.getenv("SAFEAGENT_CREDENTIALS_FILE");
        return p == null || p.isBlank() ? "data/initial_credentials.txt" : p.trim();
    }

    /** 生产口令落盘（尽力设置 POSIX 600，Windows 自动忽略）；失败则终止启动，避免凭据丢失后无法登录 */
    private static String writeInitialCredentials(String content) {
        String path = credentialsFilePath();
        try {
            Path file = Path.of(path);
            if (file.getParent() != null) Files.createDirectories(file.getParent());
            Files.writeString(file, content, StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
                    java.nio.file.StandardOpenOption.WRITE);
            try {
                Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            } catch (Exception ignore) {
                // Windows 或不支持 POSIX 权限的文件系统：忽略，依赖目录权限兜底
            }
            return file.toAbsolutePath().toString();
        } catch (IOException e) {
            throw new IllegalStateException("生产模式初始口令文件写入失败：" + path, e);
        }
    }

    /** 登录：返回 {ok, reason, locked, remain, mfa_enabled}；口令正确且未启用 MFA 时签发 token */
    public Map<String, Object> login(String username, String password) {
        return login(username, password, null);
    }

    /** 登录（支持绑定设备指纹于所签发令牌）：返回 {ok, reason, locked, remain, mfa_enabled} */
    public Map<String, Object> login(String username, String password, String deviceFp) {
        username = username == null ? "" : username.trim();
        if (username.isEmpty() || password == null || password.isEmpty()) {
            return Map.of("ok", false, "reason", "empty", "locked", false, "remain", 0);
        }
        long now = System.currentTimeMillis();
        long lock = lockUntil.getOrDefault(username, new long[]{0})[0];
        if (lock > now) {
            return Map.of("ok", false, "reason", "locked", "locked", true,
                    "remain", (lock - now) / 1000);
        }
        Map<String, Object> row = users.getPasswordRow(username);
        boolean ok = row != null && "active".equals(row.get("status"))
                && verifyPassword(password, row);
        if (!ok) {
            recordFailure(username);
            long l2 = lockUntil.getOrDefault(username, new long[]{0})[0];
            return Map.of("ok", false, "reason", "invalid",
                    "locked", l2 > now, "remain", l2 > now ? (l2 - now) / 1000 : 0);
        }
        clearFailure(username);
        boolean mfa = isMfaEnabled(username);
        boolean forceMfa = users.getForceMfa(username);
        if (forceMfa && !mfa) {
            // 强制 MFA 且未绑定 TOTP：不签发访问令牌，要求先完成 MFA 注册。
            // mfa_ticket 为 scope=mfa 临时票据（复用二步验证票据），供前端引导绑定 TOTP 的注册流程鉴权；
            // mfa_enrollment_required 为增量字段：旧前端按 mfa_enabled 走二步验证分支不受影响。
            return new LinkedHashMap<>(Map.of(
                    "ok", true,
                    "reason", "mfa_enrollment_required",
                    "locked", false,
                    "remain", 0,
                    "mfa_enabled", true,
                    "mfa_enrollment_required", true,
                    "mfa_ticket", createMfaTicket(username)));
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("ok", true);
        r.put("reason", "ok");
        r.put("locked", false);
        r.put("remain", 0);
        r.put("mfa_enabled", mfa);
        if (!mfa) {
            // 绑定设备指纹 + 当前会话版本，供令牌吊销与跨设备防护
            r.put("token", jwt.createAccessToken(username, deviceFp, users.getTokenVersion(username)));
        }
        return r;
    }

    private boolean verifyPassword(String password, Map<String, Object> row) {
        String saltHex = row.get("salt") == null ? "" : row.get("salt").toString();
        String expected = row.get("password_hash") == null ? "" : row.get("password_hash").toString();
        byte[] salt;
        try {
            salt = java.util.HexFormat.of().parseHex(saltHex);
        } catch (IllegalArgumentException e) {
            return false;
        }
        String actual = PasswordHasher.hash(password, salt);
        return PasswordHasher.constantEquals(actual, expected);
    }

    private boolean isMfaEnabled(String username) {
        Map<String, Object> m = users.getUserMfa(username);
        Object v = m.get("mfa_enabled");
        return v != null && !"0".equals(v.toString()) && !"false".equalsIgnoreCase(v.toString());
    }

    private void recordFailure(String username) {
        long now = System.currentTimeMillis();
        int[] c = loginFails.merge(username, new int[]{1}, (a, b) -> new int[]{a[0] + 1});
        if (c[0] >= maxLoginFails) {
            lockUntil.put(username, new long[]{now + lockSeconds * 1000});
            loginFails.remove(username);
        }
    }

    private void clearFailure(String username) {
        loginFails.remove(username);
        lockUntil.remove(username);
    }

    /** 弱口令策略（与 Python check_password_policy 对齐的简化实现） */
    public static String checkPasswordPolicy(String password) {
        if (password == null || password.length() < 8) return "口令长度至少 8 位";
        boolean hasLetter = password.chars().anyMatch(Character::isLetter);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        if (!hasLetter || !hasDigit) return "口令需同时包含字母和数字";
        return null;
    }

    public static boolean isValidRole(String role) {
        return role != null && ROLES.contains(role);
    }

    /** 生成/校验 MFA 临时票据（scope=mfa） */
    public String createMfaTicket(String username) {
        return jwt.createToken(username, "mfa", 300);
    }

    public String resolveMfaTicket(String token) {
        Map<String, Object> payload = jwt.decode(token);
        if (payload == null) return null;
        if (!"mfa".equals(payload.get("scope"))) return null;
        return payload.get("sub") instanceof String s ? s : null;
    }
}