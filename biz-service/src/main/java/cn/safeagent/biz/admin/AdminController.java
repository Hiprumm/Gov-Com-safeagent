package cn.safeagent.biz.admin;

import cn.safeagent.biz.auth.AuthService;
import cn.safeagent.biz.auth.UserRepository;
import cn.safeagent.biz.common.security.AuthContext;
import cn.safeagent.biz.common.util.PasswordHasher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 用户与组织管理域（仅系统管理员）。
 * 对齐 FastAPI routers/admin.py 的业务规则：用户 CRUD、部门目录、后台统计。
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserRepository users;

    public AdminController(UserRepository users) {
        this.users = users;
    }

    /** 校验 admin 身份；无权限抛 403。返回身份 Map */
    private Map<String, Object> requireAdmin(HttpServletRequest req) {
        Map<String, Object> identity = AuthContext.current(req);
        if (identity == null) throw new cn.safeagent.biz.common.exception.BizException(401, "未登录");
        if (!"admin".equals(identity.get("role"))) {
            throw new cn.safeagent.biz.common.exception.BizException(403, "无权限：需要系统管理员身份");
        }
        return identity;
    }

    @GetMapping("/users")
    public Map<String, Object> listUsers(HttpServletRequest req,
                                         @RequestParam(defaultValue = "1") int page,
                                         @RequestParam(defaultValue = "10") int pageSize) {
        requireAdmin(req);
        List<Map<String, Object>> all = users.listUsers();
        int size = Math.min(200, Math.max(1, pageSize));
        int pg = Math.max(1, page);
        int start = (pg - 1) * size;
        int end = Math.min(all.size(), start + size);
        List<Map<String, Object>> pageList = start < all.size() ? all.subList(start, end) : List.of();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("users", pageList);
        out.put("total", all.size());
        out.put("page", pg);
        out.put("page_size", size);
        return out;
    }

    @PostMapping("/users")
    public Map<String, Object> createUser(HttpServletRequest req, @RequestBody(required = false) Map<String, Object> body) {
        requireAdmin(req);
        if (body == null) body = Map.of();
        String username = String.valueOf(body.getOrDefault("username", "")).trim();
        String password = String.valueOf(body.getOrDefault("password", ""));
        String displayName = String.valueOf(body.getOrDefault("display_name", "")).trim();
        if (displayName.isEmpty()) displayName = username;
        String role = String.valueOf(body.getOrDefault("role", "")).trim();
        if (username.isEmpty()) return err("用户名不能为空");
        String pwReason = AuthService.checkPasswordPolicy(password);
        if (pwReason != null) return err(pwReason);
        if (!AuthService.isValidRole(role)) return err("角色必须为 [admin, operator, auditor, manager, user]");
        if (users.userExists(username)) return err("账号 " + username + " 已存在");
        String[] hs = PasswordHasher.hashNewSalt(password);
        users.upsertUser(username, hs[0], hs[1], displayName, role,
                String.valueOf(body.getOrDefault("department", "")).trim(),
                String.valueOf(body.getOrDefault("position", "")).trim(),
                "active", String.valueOf(body.getOrDefault("note", "")).trim());
        // 组织目录自动补录部门
        String dept = String.valueOf(body.getOrDefault("department", "")).trim();
        if (!dept.isEmpty() && !users.departmentExists(dept)) {
            users.addDepartment(dept);
        }
        return ok("已创建账号 " + username);
    }

    @PutMapping("/users/{username}")
    public Map<String, Object> updateUser(HttpServletRequest req, @PathVariable String username,
                                          @RequestBody(required = false) Map<String, Object> body) {
        Map<String, Object> actor = requireAdmin(req);
        if (!users.userExists(username)) return err("账号 " + username + " 不存在");
        if (body == null) body = Map.of();
        Object role = body.get("role");
        Object status = body.get("status");
        // 自我保护：不得降级或停用当前登录的管理员
        if (username.equals(actor.get("username"))
                && ((role != null && !"admin".equals(String.valueOf(role))) || "disabled".equals(String.valueOf(status)))) {
            return err("不能降级或停用当前登录的管理员账号");
        }
        if (role != null && !AuthService.isValidRole(String.valueOf(role))) {
            return err("角色必须为 [admin, operator, auditor, manager, user]");
        }
        users.updateProfile(username,
                body.get("display_name") == null ? null : String.valueOf(body.get("display_name")),
                role == null ? null : String.valueOf(role),
                body.get("department") == null ? null : String.valueOf(body.get("department")),
                body.get("position") == null ? null : String.valueOf(body.get("position")),
                status == null ? null : String.valueOf(status),
                body.get("note") == null ? null : String.valueOf(body.get("note")));
        return ok("已更新账号 " + username);
    }

    @PostMapping("/users/{username}/reset_password")
    public Map<String, Object> resetPassword(HttpServletRequest req, @PathVariable String username,
                                             @RequestBody(required = false) Map<String, Object> body) {
        requireAdmin(req);
        String password = body == null ? "" : String.valueOf(body.getOrDefault("password", ""));
        String reason = AuthService.checkPasswordPolicy(password);
        if (reason != null) return err(reason);
        if (!users.userExists(username)) return err("账号 " + username + " 不存在");
        String[] hs = PasswordHasher.hashNewSalt(password);
        users.updatePassword(username, hs[0], hs[1]);
        return ok("已重置账号 " + username + " 的密码");
    }

    @DeleteMapping("/users/{username}")
    public Map<String, Object> deleteUser(HttpServletRequest req, @PathVariable String username) {
        Map<String, Object> actor = requireAdmin(req);
        if (username.equals(actor.get("username"))) return err("不能删除当前登录的管理员账号");
        if (List.of("admin", "operator", "auditor", "user").contains(username)) {
            return err("内置演示账号建议用「停用」而非删除，避免破坏登录引导");
        }
        if (!users.userExists(username)) return err("账号 " + username + " 不存在");
        users.deleteUser(username);
        return ok("已删除账号 " + username);
    }

    @GetMapping("/stats")
    public Map<String, Object> stats(HttpServletRequest req) {
        requireAdmin(req);
        List<Map<String, Object>> all = users.listUsers();
        Map<String, Integer> byRole = new LinkedHashMap<>();
        Map<String, Integer> byDept = new LinkedHashMap<>();
        int active = 0, disabled = 0;
        for (Map<String, Object> u : all) {
            String role = String.valueOf(u.get("role"));
            byRole.merge(role, 1, Integer::sum);
            String d = u.get("department") == null || String.valueOf(u.get("department")).isBlank()
                    ? "未分配" : String.valueOf(u.get("department"));
            byDept.merge(d, 1, Integer::sum);
            if ("active".equals(String.valueOf(u.get("status")))) active++;
            else disabled++;
        }
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("total", all.size());
        stats.put("active", active);
        stats.put("disabled", disabled);
        stats.put("by_role", byRole);
        stats.put("by_department", byDept);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("stats", stats);
        return out;
    }

    @GetMapping("/departments")
    public Map<String, Object> listDepartments(HttpServletRequest req) {
        requireAdmin(req);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("departments", users.listDepartments());
        return out;
    }

    @PostMapping("/departments")
    public Map<String, Object> addDepartment(HttpServletRequest req, @RequestBody(required = false) Map<String, Object> body) {
        requireAdmin(req);
        String name = body == null ? "" : String.valueOf(body.getOrDefault("name", "")).trim();
        if (name.isEmpty()) return err("部门名称不能为空");
        boolean ok = users.addDepartment(name);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", ok);
        out.put("message", ok ? "已新增部门" : "部门已存在");
        return out;
    }

    @PutMapping("/departments")
    public Map<String, Object> renameDepartment(HttpServletRequest req, @RequestBody(required = false) Map<String, Object> body) {
        requireAdmin(req);
        String oldName = body == null ? "" : String.valueOf(body.getOrDefault("old_name", "")).trim();
        String newName = body == null ? "" : String.valueOf(body.getOrDefault("new_name", "")).trim();
        if (oldName.isEmpty() || newName.isEmpty()) return err("原部门名与新部门名均不能为空");
        boolean ok = users.renameDepartment(oldName, newName);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", ok);
        out.put("message", ok ? "已重命名" : "部门不存在或名称重复");
        return out;
    }

    @DeleteMapping("/departments")
    public Map<String, Object> deleteDepartment(HttpServletRequest req, @RequestParam String name) {
        requireAdmin(req);
        if (name == null || name.isBlank()) return err("部门名称不能为空");
        boolean ok = users.removeDepartment(name.trim());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", ok);
        out.put("message", ok ? "已删除部门" : "部门不存在");
        return out;
    }

    private Map<String, Object> ok(String message) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("message", message);
        return out;
    }

    private Map<String, Object> err(String message) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", false);
        out.put("error", message);
        return out;
    }
}