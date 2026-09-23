package cn.safeagent.biz.auth;

import cn.safeagent.biz.common.exception.BizException;
import cn.safeagent.biz.common.security.AuthContext;
import cn.safeagent.biz.common.security.JwtService;
import cn.safeagent.biz.common.util.LoginCipher;
import cn.safeagent.biz.common.util.Totp;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 认证域：登录 / 登出 / 当前身份 / 个人中心 / MFA / SSO 配置。
 * 对齐 FastAPI routers/auth.py 的 URL 与响应结构。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService auth;
    private final JwtService jwt;
    private final UserRepository users;
    private final LoginCipher cipher;

    public AuthController(AuthService auth, JwtService jwt, UserRepository users, LoginCipher cipher) {
        this.auth = auth;
        this.jwt = jwt;
        this.users = users;
        this.cipher = cipher;
    }

    /** 登录口令传输加密公钥下发（公开，无需登录）。前端据此用 RSA-OAEP 加密口令后提交 */
    @GetMapping("/pubkey")
    public Map<String, Object> pubkey() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("kid", cipher.getKid());
        out.put("public_pem", cipher.getPublicPem());
        return out;
    }

    @PostMapping("/login")
    public Map<String, Object> login(HttpServletRequest req, @RequestBody(required = false) Map<String, Object> body) {
        String username = body == null ? "" : String.valueOf(body.getOrDefault("username", "")).trim();
        // 优先解密前端 RSA 加密口令；未提供则退回明文字段（兼容测试脚本/工具明文调用）
        String password = null;
        String enc = body == null ? "" : String.valueOf(body.getOrDefault("enc_password", ""));
        String kid = body == null ? "" : String.valueOf(body.getOrDefault("kid", ""));
        if (enc != null && !enc.isBlank()) {
            password = cipher.decrypt(enc, kid);
            if (password == null) {
                throw BizException.badRequest("口令密文无效或已过期，请刷新页面重试");
            }
        } else {
            password = body == null ? "" : String.valueOf(body.getOrDefault("password", ""));
        }
        String devFp = JwtService.deviceFingerprint(req.getHeader("User-Agent"));
        Map<String, Object> r = auth.login(username, password, devFp);
        if (Boolean.FALSE.equals(r.get("ok"))) {
            String reason = String.valueOf(r.get("reason"));
            if ("locked".equals(reason)) {
                throw BizException.locked("账号已锁定，请 " + r.get("remain") + " 秒后重试");
            }
            throw BizException.unauthorized("用户名或密码错误");
        }
        boolean mfa = Boolean.TRUE.equals(r.get("mfa_enabled"));
        if (mfa) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("success", true);
            out.put("mfa_required", true);
            out.put("mfa_ticket", auth.createMfaTicket(username));
            out.put("username", username);
            return out;
        }
        Map<String, Object> row = users.getUser(username);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("token", r.get("token"));
        out.put("user", toUserView(username, row));
        return out;
    }

    @PostMapping("/mfa/verify")
    public Map<String, Object> mfaVerify(HttpServletRequest req, @RequestBody(required = false) Map<String, Object> body) {
        String ticket = body == null ? "" : String.valueOf(body.getOrDefault("ticket", ""));
        String code = body == null ? "" : String.valueOf(body.getOrDefault("code", ""));
        String username = auth.resolveMfaTicket(ticket);
        if (username == null) throw BizException.unauthorized("验证票据无效或已过期，请重新登录");
        Map<String, Object> mfa = users.getUserMfa(username);
        boolean enabled = mfa.get("totp_secret") != null
                && !String.valueOf(mfa.get("totp_secret")).isBlank();
        if (!enabled) throw BizException.badRequest("该账号未启用 MFA");
        String secret = String.valueOf(mfa.get("totp_secret"));
        if (!Totp.verify(secret, code)) {
            throw BizException.unauthorized("验证码不正确");
        }
        Map<String, Object> row = users.getUser(username);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("token", jwt.createAccessToken(username,
                JwtService.deviceFingerprint(req.getHeader("User-Agent")), users.getTokenVersion(username)));
        out.put("user", toUserView(username, row));
        return out;
    }

    @PostMapping("/logout")
    public Map<String, Object> logout(HttpServletRequest req) {
        // jti 黑名单为进程内状态；阶段1登出仅丢弃前端本地 token。如需即时撤销可扩展 blacklist。
        return Map.of("success", true);
    }

    @GetMapping("/me")
    public Map<String, Object> me(HttpServletRequest req) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("user", AuthContext.current(req));
        out.put("demo_accounts", demoAccounts());
        return out;
    }

    @GetMapping("/permissions")
    public Map<String, Object> permissions(HttpServletRequest req) {
        Map<String, Object> identity = AuthContext.current(req);
        String role = identity == null ? "" : String.valueOf(identity.getOrDefault("role", ""));
        String r = role == null ? "" : role.trim().toLowerCase();
        List<String> perms = permsFor(r);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("role", role);
        out.put("permissions", perms);
        out.put("modules", modulesFor(r));
        out.put("data_scope", dataScope(r));
        out.put("can_approve_approval", perms.contains("approval.approve"));
        out.put("is_admin", "admin".equals(r));
        return out;
    }

    // 权限点矩阵 —— 与 FastAPI security/permission_engine.py 的 ROLE_PERMISSIONS 对齐（单一事实来源）
    private List<String> permsFor(String role) {
        return switch (role) {
            case "admin" -> List.of("chat.use", "dashboard.view", "runtime.view", "runtime.terminate",
                    "security.detect", "security.scan", "redteam.run", "tools.view", "tools.manage",
                    "approval.view", "approval.approve", "audit.view", "audit.export",
                    "policy.view", "policy.manage", "system.view", "system.maintain", "admin.manage");
            case "operator" -> List.of("chat.use", "dashboard.view", "runtime.view", "runtime.terminate",
                    "security.detect", "security.scan", "tools.view", "tools.manage",
                    "approval.view", "approval.approve", "audit.view");
            case "auditor" -> List.of("chat.use", "dashboard.view", "approval.view", "audit.view", "audit.export");
            case "manager" -> List.of("chat.use", "dashboard.view", "approval.view", "approval.approve", "audit.view");
            case "user" -> List.of("chat.use", "dashboard.view", "audit.view");
            default -> List.of();
        };
    }

    private List<String> modulesFor(String role) {
        List<String> p = permsFor(role);
        Map<String, String> mp = Map.ofEntries(
                Map.entry("chat", "chat.use"), Map.entry("dashboard", "dashboard.view"),
                Map.entry("runtime", "runtime.view"), Map.entry("security", "security.detect"),
                Map.entry("redteam", "redteam.run"), Map.entry("tools", "tools.view"),
                Map.entry("approval", "approval.view"), Map.entry("audit", "audit.view"),
                Map.entry("policy", "policy.view"), Map.entry("system", "system.view"),
                Map.entry("governance", "system.maintain"));
        return List.of("chat", "dashboard", "runtime", "security", "redteam", "tools",
                        "approval", "audit", "policy", "system", "governance").stream()
                .filter(m -> p.contains(mp.get(m)))
                .toList();
    }

    private String dataScope(String role) {
        return switch (role) {
            case "admin", "operator", "auditor" -> "all";
            case "manager" -> "dept";
            case "user", "self" -> "self";
            default -> "self";
        };
    }

    @PutMapping("/profile")
    public Map<String, Object> profile(HttpServletRequest req, @RequestBody(required = false) Map<String, Object> body) {
        Map<String, Object> identity = AuthContext.current(req);
        if (identity == null) throw BizException.unauthorized("未登录或登录已过期");
        String username = String.valueOf(identity.get("username"));
        String displayName = body == null ? "" : String.valueOf(body.getOrDefault("display_name", "")).trim();
        if (displayName.isEmpty()) throw BizException.unprocessable("显示名不能为空");
        if (displayName.length() > 20) throw BizException.unprocessable("显示名长度不能超过 20 个字符");
        int n = users.updateProfile(username, displayName, null, null, null, null, null);
        if (n <= 0) throw BizException.server("资料保存失败，请稍后重试");
        Map<String, Object> row = users.getUser(username);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("user", toUserView(username, row));
        return out;
    }

    @PostMapping("/password")
    public Map<String, Object> changePassword(HttpServletRequest req, @RequestBody(required = false) Map<String, Object> body) {
        Map<String, Object> identity = AuthContext.current(req);
        if (identity == null) throw BizException.unauthorized("未登录");
        String username = String.valueOf(identity.get("username"));
        String oldPw = body == null ? "" : String.valueOf(body.getOrDefault("old_password", ""));
        String newPw = body == null ? "" : String.valueOf(body.getOrDefault("new_password", ""));
        Map<String, Object> row = users.getPasswordRow(username);
        if (row == null || !verify(oldPw, row)) throw BizException.badRequest("原口令不正确");
        String reason = AuthService.checkPasswordPolicy(newPw);
        if (reason != null) throw BizException.badRequest(reason);
        String[] hs = cn.safeagent.biz.common.util.PasswordHasher.hashNewSalt(newPw);
        users.updatePassword(username, hs[0], hs[1]);
        users.incrementTokenVersion(username); // 改密后旧令牌立即失效
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("message", "口令已更新，请使用新口令登录");
        return out;
    }

    @GetMapping("/sso/config")
    public Map<String, Object> ssoConfig() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("sso_enabled", false);
        out.put("header", "X-Remote-User");
        out.put("signature_required", false);
        out.put("ip_restricted", false);
        return out;
    }

    private boolean verify(String password, Map<String, Object> row) {
        String saltHex = row.get("salt") == null ? "" : String.valueOf(row.get("salt"));
        byte[] salt;
        try { salt = java.util.HexFormat.of().parseHex(saltHex); }
        catch (IllegalArgumentException e) { return false; }
        String expected = row.get("password_hash") == null ? "" : String.valueOf(row.get("password_hash"));
        return cn.safeagent.biz.common.util.PasswordHasher.constantEquals(
                cn.safeagent.biz.common.util.PasswordHasher.hash(password, salt), expected);
    }

    private List<Map<String, Object>> demoAccounts() {
        List<Map<String, Object>> usersList = users.listUsers();
        return usersList.stream()
                .filter(u -> List.of("admin", "operator", "auditor", "user").contains(String.valueOf(u.get("username"))))
                .map(u -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("username", u.get("username"));
                    m.put("display_name", u.get("display_name"));
                    m.put("role", u.get("role"));
                    m.put("department", u.get("department"));
                    m.put("position", u.get("position"));
                    m.put("password_hint", "admin123");
                    return m;
                })
                .toList();
    }

    private Map<String, Object> toUserView(String username, Map<String, Object> row) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("username", username);
        m.put("display_name", row == null ? username : row.getOrDefault("display_name", username));
        m.put("role", row == null ? "user" : row.getOrDefault("role", "user"));
        m.put("department", row == null ? "" : row.getOrDefault("department", ""));
        m.put("position", row == null ? "" : row.getOrDefault("position", ""));
        return m;
    }
}