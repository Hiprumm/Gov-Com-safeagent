package cn.safeagent.biz.audit;

import cn.safeagent.biz.common.security.AuthContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 审计读取域（登录 + ABAC 数据范围收敛；导出需 audit.export 权限）。
 * 对齐 FastAPI routers/audit.py 的读端点；验签/锚点/TSA/归档等强绑 AI 的写端点留在 FastAPI。
 * 授权边界由轻量网关 + 本层双重把关。
 */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditRepository repo;
    private final AuditService auditService;

    public AuditController(AuditRepository repo, AuditService auditService) {
        this.repo = repo;
        this.auditService = auditService;
    }

    /** 登录身份；未登录抛 401 */
    private Map<String, Object> requireLogin(HttpServletRequest req) {
        Map<String, Object> id = AuthContext.current(req);
        if (id == null) throw new cn.safeagent.biz.common.exception.BizException(401, "未登录");
        return id;
    }

    /** 登录身份 + scope 过滤上下文 */
    private ScopeCtx scopeCtx(HttpServletRequest req) {
        Map<String, Object> id = requireLogin(req);
        ScopeCtx ctx = new ScopeCtx();
        ctx.subject = id;
        ctx.scope = auditService.dataScope(id);
        return ctx;
    }

    private static final class ScopeCtx { String scope; Map<String, Object> subject; }

    @GetMapping("/logs/recent")
    public Map<String, Object> recent(HttpServletRequest req, @RequestParam(defaultValue = "100") int limit) {
        ScopeCtx ctx = scopeCtx(req);
        limit = Math.min(5000, Math.max(1, limit));
        List<Map<String, Object>> rows = repo.recent(limit).stream().map(repo::parseRow).toList();
        rows = auditService.filterByScope(ctx.scope, ctx.subject, rows);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("logs", rows);
        out.put("scope", ctx.scope);
        return out;
    }

    @GetMapping("/logs/page")
    public Map<String, Object> page(HttpServletRequest req, @RequestParam(defaultValue = "1") int page,
                                    @RequestParam(defaultValue = "20") int pageSize) {
        ScopeCtx ctx = scopeCtx(req);
        page = Math.max(1, page);
        pageSize = Math.min(100, Math.max(1, pageSize));
        if ("all".equals(ctx.scope)) {
            long total = repo.count();
            List<Map<String, Object>> logs = repo.page(page, pageSize).stream().map(repo::parseRow).toList();
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("total", total);
            out.put("page", page);
            out.put("page_size", pageSize);
            out.put("pages", (total + pageSize - 1) / pageSize);
            out.put("logs", logs);
            out.put("scope", ctx.scope);
            return out;
        }
        // 非全平台：取窗口过滤后再分页，保证 total 口径一致
        int window = Math.min(20000, Math.max(page * pageSize * 5, 2000));
        List<Map<String, Object>> rows = auditService.filterByScope(ctx.scope, ctx.subject,
                repo.recent(window).stream().map(repo::parseRow).toList());
        int total = rows.size();
        int start = (page - 1) * pageSize;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("logs", start < total ? rows.subList(start, Math.min(total, start + pageSize)) : List.of());
        out.put("total", total);
        out.put("page", page);
        out.put("page_size", pageSize);
        out.put("pages", (total + pageSize - 1) / pageSize);
        out.put("scope", ctx.scope);
        return out;
    }

    @GetMapping("/logs/{logId}")
    public Map<String, Object> byId(@PathVariable String logId) {
        Map<String, Object> row = repo.byId(logId);
        if (row == null) throw new cn.safeagent.biz.common.exception.BizException(404, "日志不存在");
        return row;
    }

    @PostMapping("/logs/search")
    public Map<String, Object> search(HttpServletRequest req,
                                      @RequestParam(required = false) String user_id,
                                      @RequestParam(required = false) String agent_id,
                                      @RequestParam(required = false) String risk_level,
                                      @RequestParam(required = false) String action_type,
                                      @RequestParam(required = false) String is_blocked) {
        ScopeCtx ctx = scopeCtx(req);
        Boolean blocked = null;
        if (is_blocked != null && !is_blocked.isBlank()) blocked = Boolean.parseBoolean(is_blocked);
        List<Map<String, Object>> rows = repo.search(user_id, agent_id, risk_level, action_type, blocked, 1000);
        rows = auditService.filterByScope(ctx.scope, ctx.subject, rows);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("logs", rows);
        out.put("scope", ctx.scope);
        return out;
    }

    /** 审计导出（需 audit.export 权限） */
    @GetMapping(value = "/export", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> export(HttpServletRequest req,
                                      @RequestParam(defaultValue = "json") String format,
                                      @RequestParam(required = false) String risk_level,
                                      @RequestParam(required = false) String user_id,
                                      @RequestParam(required = false) String action_type,
                                      @RequestParam(defaultValue = "1000") int limit) {
        Map<String, Object> exporter = requireLogin(req);
        String role = String.valueOf(exporter.get("role") == null ? "" : exporter.get("role")).trim().toLowerCase();
        if (!List.of("admin", "auditor").contains(role)) {
            throw new cn.safeagent.biz.common.exception.BizException(403, "无权限：需要审计导出权限");
        }
        limit = Math.max(1, Math.min(limit, 5000));
        // 导出为全量（不做行级收敛，保持管理口径）
        List<Map<String, Object>> logs = repo.search(user_id, null, risk_level, action_type, null, limit);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("format", format);
        out.put("count", logs.size());
        if ("csv".equals(format)) {
            out.put("data", toCsv(logs));
        } else {
            out.put("logs", logs);
        }
        return out;
    }

    @GetMapping("/stats")
    public Map<String, Object> stats(@RequestParam(defaultValue = "24") int hours) {
        List<Map<String, Object>> logs = repo.recent(5000); // 原始行
        LocalDateTime cutoff = LocalDateTime.now().minusHours(hours);
        DateTimeFormatter ts = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
        List<Map<String, Object>> filtered = new java.util.ArrayList<>();
        for (Map<String, Object> log : logs) {
            try {
                LocalDateTime t = LocalDateTime.parse(String.valueOf(log.get("timestamp")), ts);
                if (t.isAfter(cutoff)) filtered.add(log);
            } catch (Exception ignored) { }
        }
        int total = filtered.size();
        int blocked = (int) filtered.stream().filter(r -> isTrue(r.get("is_blocked"))).count();
        Map<String, Integer> riskOrder = new LinkedHashMap<>();
        Map<String, Integer> actionDist = new LinkedHashMap<>();
        Map<String, Integer> userActivity = new LinkedHashMap<>();
        for (Map<String, Object> r : filtered) {
            riskOrder.merge(String.valueOf(r.get("risk_level")), 1, Integer::sum);
            actionDist.merge(String.valueOf(r.get("action_type")), 1, Integer::sum);
            userActivity.merge(String.valueOf(r.get("user_id")), 1, Integer::sum);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("period", "最近" + hours + "小时");
        out.put("total_logs", total);
        out.put("blocked_count", blocked);
        out.put("blocked_rate", total > 0 ? Math.round(blocked * 1000.0 / total) / 10.0 : 0);
        out.put("risk_distribution", riskOrder);
        out.put("action_distribution", topN(actionDist, 20));
        out.put("top_users", topN(userActivity, 10));
        return out;
    }

    private static boolean isTrue(Object v) {
        if (v instanceof Boolean b) return b;
        if (v instanceof Number n) return n.intValue() != 0;
        return "true".equalsIgnoreCase(String.valueOf(v));
    }

    private static Map<String, Object> topN(Map<String, Integer> src, int n) {
        return src.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .limit(n)
                .collect(java.util.LinkedHashMap::new, (m, e) -> m.put(e.getKey(), e.getValue()), Map::putAll);
    }

    private static String toCsv(List<Map<String, Object>> logs) {
        StringBuilder sb = new StringBuilder("log_id,timestamp,user_id,user_role,agent_id,action_type,action_details,risk_level,is_blocked,blocking_reason\n");
        for (Map<String, Object> d : logs) {
            sb.append(String.valueOf(d.get("log_id"))).append(",")
              .append(csv(String.valueOf(d.get("timestamp")))).append(",")
              .append(csv(String.valueOf(d.get("user_id")))).append(",")
              .append(csv(String.valueOf(d.get("user_role")))).append(",")
              .append(csv(String.valueOf(d.get("agent_id")))).append(",")
              .append(csv(String.valueOf(d.get("action_type")))).append(",")
              .append(csv(jsonStr(d.get("action_details")))).append(",")
              .append(csv(String.valueOf(d.get("risk_level")))).append(",")
              .append(isTrue(d.get("is_blocked"))).append(",")
              .append(csv(String.valueOf(d.get("blocking_reason")))).append("\n");
        }
        return sb.toString();
    }

    private static String jsonStr(Object v) {
        if (v == null) return "";
        try { return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(v); }
        catch (Exception e) { return String.valueOf(v); }
    }

    private static String csv(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }
}