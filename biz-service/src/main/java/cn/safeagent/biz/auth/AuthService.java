package cn.safeagent.biz.auth;

import cn.safeagent.biz.common.config.AppProperties;
import cn.safeagent.biz.common.security.JwtService;
import cn.safeagent.biz.common.util.PasswordHasher;
import org.springframework.stereotype.Service;

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

    private static final List<String> ROLES = List.of("admin", "operator", "auditor", "manager", "user");

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
        seedIfEmpty();
    }

    private void seedIfEmpty() {
        if (users.countUsers() > 0) return;
        String password = "admin123";
        for (String line : DEMO) {
            String[] p = line.split(":");
            String[] hs = PasswordHasher.hashNewSalt(password);
            users.upsertUser(p[0], hs[0], hs[1], p[1], p[2], p[3], p[4], "active", "");
        }
    }

    /** 登录：返回 {ok, reason, locked, remain, mfa_enabled}；口令正确且未启用 MFA 时签发 token */
    public Map<String, Object> login(String username, String password) {
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
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("ok", true);
        r.put("reason", "ok");
        r.put("locked", false);
        r.put("remain", 0);
        r.put("mfa_enabled", mfa);
        if (!mfa) {
            r.put("token", jwt.createToken(username));
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