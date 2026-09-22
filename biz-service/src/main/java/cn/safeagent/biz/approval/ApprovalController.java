package cn.safeagent.biz.approval;

import cn.safeagent.biz.common.security.AuthContext;
import cn.safeagent.biz.common.exception.BizException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 审批流管理端点（表 approval_requests 归属 Spring）。
 * 对齐 FastAPI ai_service/routers/security.py 的审批 API + permission_engine 的角色审批能力。
 * 授权边界由轻量网关统一鉴权把关；本层对查询要求已登录，审批/驳回动作再按角色能力校验。
 *
 * 路由顺序告警：静态段（/pending、/history、/status）必须注册在 /{request_id} 之前，
 * 否则 "pending" 会被当作 request_id（复刻 FastAPI 历史缺陷教训）。
 */
@RestController
@RequestMapping("/api/security/approval")
public class ApprovalController {

    /** 角色 → 审批时可代理的审批角色（对齐 APPROVER_ROLE_BY_ROLE） */
    private static final Map<String, String> APPROVER_ROLE_BY_ROLE = Map.of(
            "admin", "admin",
            "operator", "manager",
            "manager", "manager"
    );

    private final ApprovalRepository repo;

    public ApprovalController(ApprovalRepository repo) {
        this.repo = repo;
    }

    // ---- 静态段路由（必须在 /{request_id} 之前） ----

    @GetMapping("/pending")
    public Map<String, Object> pending(HttpServletRequest req) {
        requireApprovalView(req);
        List<Map<String, Object>> pending = repo.listPending();
        pending.forEach(this::normalizeToolArgs);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("pending", pending);
        out.put("count", pending.size());
        return out;
    }

    @GetMapping("/history")
    public Map<String, Object> history(@RequestParam(defaultValue = "50") int limit, HttpServletRequest req) {
        requireApprovalView(req);
        List<Map<String, Object>> records = repo.listRecent(limit);
        Map<String, Object> stats = new LinkedHashMap<>();
        for (Map<String, Object> r : records) {
            String status = String.valueOf(r.get("status"));
            stats.merge(status, 1, (o, n) -> ((Number) o).intValue() + 1);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("records", records);
        out.put("count", records.size());
        out.put("stats", stats);
        return out;
    }

    @GetMapping("/status/{requestId}")
    public Map<String, Object> status(@PathVariable String requestId, HttpServletRequest req) {
        requireLogin(req);
        Map<String, Object> rec = repo.get(requestId);
        if (rec == null) throw new BizException(404, "审批请求不存在");
        normalizeToolArgs(rec);
        return rec;
    }

    // ---- 参数化路由 ----

    @GetMapping("/{requestId}")
    public Map<String, Object> get(HttpServletRequest req, @PathVariable String requestId) {
        requireApprovalView(req);
        Map<String, Object> rec = repo.get(requestId);
        if (rec == null) throw new BizException(404, "审批请求不存在");
        normalizeToolArgs(rec);
        return rec;
    }

    @PostMapping("/approve/{requestId}")
    public Map<String, Object> approve(@PathVariable String requestId,
                                       @RequestBody(required = false) Map<String, Object> body,
                                       HttpServletRequest req) {
        Map<String, Object> identity = requireApprovalApprover(req);
        String approverId = str(identity.get("username"));
        String role = str(identity.get("role"));
        String approverRole = approverRoleFor(role);
        String comment = body == null ? "" : str(body.get("comment"));
        boolean updated = repo.approve(requestId, approverId, approverRole, comment);
        if (!updated) {
            Map<String, Object> rec = repo.get(requestId);
            String current = rec == null ? null : str(rec.get("status"));
            if (!"approved".equals(current) && !"auto_approved".equals(current)) {
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("success", false);
                err.put("message", "审批未通过: " + (current == null ? "not_found" : current));
                return err;
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("message", "请求 " + requestId + " 已审批通过");
        return out;
    }

    @PostMapping("/reject/{requestId}")
    public Map<String, Object> reject(@PathVariable String requestId,
                                      @RequestBody(required = false) Map<String, Object> body,
                                      HttpServletRequest req) {
        Map<String, Object> identity = requireApprovalApprover(req);
        String approverId = str(identity.get("username"));
        String reason = body == null ? "" : str(body.get("reason"));
        boolean updated = repo.reject(requestId, approverId, reason);
        Map<String, Object> rec = repo.get(requestId);
        String current = rec == null ? null : str(rec.get("status"));
        if (!updated && !("rejected".equals(current) || "approved".equals(current) || "auto_approved".equals(current))) {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("success", false);
            err.put("message", "审批请求 " + requestId + " 不存在或已处理");
            return err;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("message", "请求 " + requestId + " 已驳回");
        return out;
    }

    // ==================== 鉴权与角色能力 ====================

    private Map<String, Object> requireLogin(HttpServletRequest req) {
        Map<String, Object> id = AuthContext.current(req);
        if (id == null) throw new BizException(401, "未登录");
        return id;
    }

    private void requireApprovalView(HttpServletRequest req) {
        Map<String, Object> id = requireLogin(req);
        String role = str(id.get("role")).toLowerCase();
        // 对齐 approval.view：admin/operator/auditor/manager 可见
        if (!List.of("admin", "operator", "auditor", "manager").contains(role)) {
            throw new BizException(403, "无权限：需要审批查看权限");
        }
    }

    private Map<String, Object> requireApprovalApprover(HttpServletRequest req) {
        Map<String, Object> id = requireLogin(req);
        String role = str(id.get("role")).toLowerCase();
        String approverRole = approverRoleFor(role);
        if (approverRole == null) {
            throw new BizException(403, "当前账号无审批权限（需系统管理员 / 安全运维 / 部门负责人）");
        }
        return id;
    }

    private String approverRoleFor(String role) {
        return APPROVER_ROLE_BY_ROLE.get(str(role).toLowerCase());
    }

    /** 将 tool_args(JSON 字符串) 反序列化为对象，与 FastAPI ApprovalRequest 行为一致 */
    private void normalizeToolArgs(Map<String, Object> row) {
        Object args = row.get("tool_args");
        if (args instanceof String s) {
            if (!s.isBlank()) {
                try {
                    row.put("tool_args", new com.fasterxml.jackson.databind.ObjectMapper().readValue(s, Object.class));
                } catch (Exception e) {
                    row.put("tool_args", s);
                }
            } else {
                row.put("tool_args", new LinkedHashMap<>());
            }
        }
    }

    private static String str(Object v) {
        return v == null ? "" : String.valueOf(v);
    }
}