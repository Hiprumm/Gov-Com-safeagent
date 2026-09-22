package cn.safeagent.biz.governance;

import cn.safeagent.biz.common.security.AuthContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 治理域：应急联动 / 开放生态 / PIPL 合规台账。
 * 对齐 FastAPI routers/governance.py，授权边界由轻量网关统一鉴权把关
 * （POST→system.maintain，GET→system.view），本层读取操作人身份。
 */
@RestController
public class GovernanceController {

    private final GovernanceRepository repo;
    private final cn.safeagent.biz.audit.AuditService audit;

    public GovernanceController(GovernanceRepository repo, cn.safeagent.biz.audit.AuditService audit) {
        this.repo = repo;
        this.audit = audit;
    }

    private String operator(HttpServletRequest req) {
        Map<String, Object> id = AuthContext.current(req);
        if (id == null) return "system";
        Object u = id.get("username");
        return u == null ? "system" : String.valueOf(u);
    }

    // ==================== 应急联动 /api/emergency ====================

    @GetMapping("/api/emergency/status")
    public Map<String, Object> emergencyStatus() {
        SetVals sv = currentControlSets();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("global_engaged", sv.global);
        out.put("blocked_users", sv.users.stream().sorted().toList());
        out.put("blocked_ips", sv.ips.stream().sorted().toList());
        out.put("active", repo.activeEmergencyControls());
        out.put("history", repo.emergencyHistory(30));
        return out;
    }

    private static final class SetVals {
        boolean global;
        final java.util.Set<String> users = new java.util.LinkedHashSet<>();
        final java.util.Set<String> ips = new java.util.LinkedHashSet<>();
    }

    private SetVals currentControlSets() {
        SetVals sv = new SetVals();
        for (Map<String, Object> row : repo.activeEmergencyControls()) {
            String type = String.valueOf(row.get("control_type"));
            Object target = row.get("target");
            String t = target == null ? "" : String.valueOf(target);
            switch (type) {
                case "global_circuit" -> sv.global = true;
                case "block_user" -> sv.users.add(t);
                case "block_ip" -> sv.ips.add(t);
                default -> { }
            }
        }
        return sv;
    }

    @PostMapping("/api/emergency/engage")
    public Map<String, Object> engage(@RequestBody(required = false) Map<String, Object> body, HttpServletRequest req) {
        String reason = body == null ? "" : String.valueOf(body.getOrDefault("reason", ""));
        String op = operator(req);
        repo.addEmergencyControl("global_circuit", "*", op, reason);
        writeAudit("emergency_circuit_break", reason, op);
        return ok("global_circuit");
    }

    @PostMapping("/api/emergency/disengage")
    public Map<String, Object> disengage(HttpServletRequest req) {
        String op = operator(req);
        repo.releaseEmergencyControl("global_circuit", "*");
        writeAudit("emergency_circuit_break", "disengage:" + op, op);
        return ok("global_circuit");
    }

    @PostMapping("/api/emergency/block_user")
    public Map<String, Object> blockUser(@RequestBody(required = false) Map<String, Object> body, HttpServletRequest req) {
        String name = body == null ? "" : String.valueOf(body.getOrDefault("username", "")).trim();
        String reason = body == null ? "" : String.valueOf(body.getOrDefault("reason", ""));
        String op = operator(req);
        repo.addEmergencyControl("block_user", name, op, reason);
        writeAudit("emergency_block_user", reason, op);
        return simpleOk();
    }

    @PostMapping("/api/emergency/unblock_user")
    public Map<String, Object> unblockUser(@RequestBody(required = false) Map<String, Object> body, HttpServletRequest req) {
        String name = body == null ? "" : String.valueOf(body.getOrDefault("username", "")).trim();
        String op = operator(req);
        repo.releaseEmergencyControl("block_user", name);
        writeAudit("emergency_unblock_user", name, op);
        return simpleOk();
    }

    @PostMapping("/api/emergency/block_ip")
    public Map<String, Object> blockIp(@RequestBody(required = false) Map<String, Object> body, HttpServletRequest req) {
        String ip = body == null ? "" : String.valueOf(body.getOrDefault("ip", "")).trim();
        String reason = body == null ? "" : String.valueOf(body.getOrDefault("reason", ""));
        String op = operator(req);
        repo.addEmergencyControl("block_ip", ip, op, reason);
        writeAudit("emergency_block_ip", reason, op);
        return simpleOk();
    }

    @PostMapping("/api/emergency/unblock_ip")
    public Map<String, Object> unblockIp(@RequestBody(required = false) Map<String, Object> body, HttpServletRequest req) {
        String ip = body == null ? "" : String.valueOf(body.getOrDefault("ip", "")).trim();
        String op = operator(req);
        repo.releaseEmergencyControl("block_ip", ip);
        writeAudit("emergency_unblock_ip", ip, op);
        return simpleOk();
    }

    // ==================== 开放生态 /api/ecosystem ====================

    @GetMapping("/api/ecosystem/clients")
    public Map<String, Object> ecosystemClients() {
        List<Map<String, Object>> clients = repo.listApiClients();
        clients.forEach(c -> c.remove("token_hash"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("clients", clients);
        out.put("client_count", clients.size());
        long totalUsed = clients.stream().mapToLong(c -> toLong(c.get("used"))).sum();
        out.put("total_used", totalUsed);
        return out;
    }

    @PostMapping("/api/ecosystem/create")
    public Map<String, Object> ecosystemCreate(@RequestBody(required = false) Map<String, Object> body, HttpServletRequest req) {
        String name = body == null ? "" : String.valueOf(body.getOrDefault("name", "")).trim();
        int rate = (int) Math.min(10000, Math.max(1, toLong(body == null ? null : body.get("rate_limit")) != 0
                ? toLong(body.get("rate_limit")) : 60));
        int quota = (int) Math.max(0, toLong(body == null ? null : body.get("quota")));
        String desc = body == null ? "" : String.valueOf(body.getOrDefault("description", ""));
        String clientId = "cli_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String token = "sag_" + UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        repo.upsertApiClient(clientId, name, sha256("openapis:" + token), 1, rate, quota, operator(req), desc);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("client_id", clientId);
        out.put("token", token);
        out.put("token_note", "令牌仅本次显示，请立即妥善保存（系统仅存哈希，无法二次查看）");
        return out;
    }

    @PostMapping("/api/ecosystem/toggle")
    public Map<String, Object> ecosystemToggle(@RequestBody(required = false) Map<String, Object> body) {
        String clientId = body == null ? "" : String.valueOf(body.getOrDefault("client_id", "")).trim();
        boolean enabled = body != null && Boolean.TRUE.equals(body.get("enabled"));
        Map<String, Object> c = repo.getApiClient(clientId);
        if (c == null) return err("调用方不存在");
        repo.upsertApiClient(clientId, String.valueOf(c.get("name")), String.valueOf(c.get("token_hash")),
                enabled ? 1 : 0, (int) toLong(c.get("rate_limit")), (int) toLong(c.get("quota")), "",
                String.valueOf(c.getOrDefault("description", "")));
        return simpleOk();
    }

    @PostMapping("/api/ecosystem/delete")
    public Map<String, Object> ecosystemDelete(@RequestBody(required = false) Map<String, Object> body) {
        String clientId = body == null ? "" : String.valueOf(body.getOrDefault("client_id", "")).trim();
        repo.deleteApiClient(clientId);
        return simpleOk();
    }

    @GetMapping("/api/ecosystem/logs")
    public Map<String, Object> ecosystemLogs(@RequestParam(defaultValue = "100") int limit) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("logs", repo.listApiCallLogs(limit));
        return out;
    }

    // ==================== PIPL 合规台账 /api/pipl ====================

    @GetMapping("/api/pipl/records")
    public Map<String, Object> piplRecords() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("records", repo.listPiplRecords(200));
        out.putAll(repo.piplStats());
        return out;
    }

    @PostMapping("/api/pipl/update")
    public Map<String, Object> piplUpdate(@RequestBody(required = false) Map<String, Object> body, HttpServletRequest req) {
        int id = (int) toLong(body == null ? null : body.get("id"));
        String legal = body == null ? "" : String.valueOf(body.getOrDefault("legal_basis", ""));
        String assess = body == null ? "" : String.valueOf(body.getOrDefault("assessment", "pending"));
        if (!List.of("pending", "合规", "不合规-需整改").contains(assess)) return err("评估结论取值非法");
        repo.updatePiplRecord(id, legal, assess, operator(req));
        return simpleOk();
    }

    @PostMapping("/api/pipl/scan")
    public Map<String, Object> piplScan(@RequestBody(required = false) Map<String, Object> body, HttpServletRequest req) {
        String text = body == null ? "" : String.valueOf(body.getOrDefault("text", ""));
        String sid = body == null ? "" : String.valueOf(body.getOrDefault("session_id", ""));
        String source = body == null ? "" : String.valueOf(body.getOrDefault("source", "manual"));
        String op = operator(req);
        java.util.List<Map<String, Object>> found = new java.util.ArrayList<>();
        for (PiiPattern pp : PiiPattern.ALL) {
            Matcher m = pp.pattern.matcher(text == null ? "" : text);
            while (m.find()) {
                String masked = mask(text, m.start(), m.end());
                repo.addPiplRecord(sid, op, pp.label, masked, source);
                Map<String, Object> hit = new LinkedHashMap<>();
                hit.put("type", pp.label);
                hit.put("masked", masked);
                found.add(hit);
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("found_count", found.size());
        out.put("found", found);
        return out;
    }

    @GetMapping("/api/pipl/export")
    public Map<String, Object> piplExport(@RequestParam(defaultValue = "csv") String fmt,
                                          HttpServletRequest req) {
        if (!fmt.equals("csv") && !fmt.equals("json")) throw new cn.safeagent.biz.common.exception.BizException(400, "fmt 仅支持 csv/json");
        List<Map<String, Object>> items = repo.listPiplRecords(5000);
        StringBuilder sb = new StringBuilder();
        String filename;
        if (fmt.equals("json")) {
            sb.append("[");
            for (int i = 0; i < items.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append("{\"id\":").append(items.get(i).get("id"))
                  .append(",\"time\":\"").append(esc(String.valueOf(items.get(i).get("created_at"))))
                  .append("\",\"user\":\"").append(esc(String.valueOf(items.get(i).get("username"))))
                  .append("\",\"type\":\"").append(esc(String.valueOf(items.get(i).get("pii_type"))))
                  .append("\",\"masked\":\"").append(esc(String.valueOf(items.get(i).get("masked_value"))))
                  .append("\",\"legal_basis\":\"").append(esc(String.valueOf(items.get(i).get("legal_basis"))))
                  .append("\",\"assessment\":\"").append(esc(String.valueOf(items.get(i).get("assessment"))))
                  .append("\"}");
            }
            sb.append("]");
            filename = "pipl_records.json";
        } else {
            sb.append("id,time,user,type,masked,legal_basis,assessment\n");
            for (Map<String, Object> r : items) {
                sb.append(r.get("id")).append(",")
                  .append(csv(String.valueOf(r.get("created_at")))).append(",")
                  .append(csv(String.valueOf(r.get("username")))).append(",")
                  .append(csv(String.valueOf(r.get("pii_type")))).append(",")
                  .append(csv(String.valueOf(r.get("masked_value")))).append(",")
                  .append(csv(String.valueOf(r.get("legal_basis")))).append(",")
                  .append(csv(String.valueOf(r.get("assessment")))).append("\n");
            }
            filename = "pipl_records.csv";
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("fmt", fmt);
        out.put("filename", filename);
        out.put("content", sb.toString());
        out.put("count", items.size());
        return out;
    }

    // ==================== 审计留痕（治理动作写 audit_logs；表归 Spring，读取由 audit 域提供） ====================

    private void writeAudit(String actionType, String details, String operator) {
        try {
            audit.record(actionType, operator, details);
        } catch (Exception ignored) { }
    }

    // ==================== 工具 ====================

    private Map<String, Object> ok(String controlType) {
        boolean engaged = !repo.activeEmergencyControls().isEmpty()
                && repo.activeEmergencyControls().stream().anyMatch(r -> "global_circuit".equals(String.valueOf(r.get("control_type"))));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("engaged", engaged);
        out.put("control_type", controlType);
        return out;
    }

    private Map<String, Object> simpleOk() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        return out;
    }

    private Map<String, Object> err(String message) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", false);
        out.put("error", message);
        return out;
    }

    private static long toLong(Object v) {
        if (v == null) return 0;
        if (v instanceof Number n) return n.longValue();
        try { return Long.parseLong(String.valueOf(v)); } catch (NumberFormatException e) { return 0; }
    }

    private static String mask(String text, int s, int e) {
        if (s < 0 || e > text.length() || s >= e) return "";
        String val = text.substring(s, e);
        int len = val.length();
        if (len <= 4) return len == 0 ? "" : val.charAt(0) + "*".repeat(len - 1);
        return val.substring(0, 3) + "*".repeat(len - 6) + val.substring(len - 3);
    }

    private static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : d) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String csv(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    // PII 识别模式（与 Python governance.PII_PATTERNS 对齐）
    private record PiiPattern(String label, Pattern pattern) {
        private static final java.util.List<PiiPattern> ALL = java.util.List.of(
                new PiiPattern("手机号", Pattern.compile("1[3-9]\\d{9}")),
                new PiiPattern("身份证号", Pattern.compile("\\d{17}[\\dXx]")),
                new PiiPattern("护照号", Pattern.compile("(?i)(?<!\\w)[A-Za-z]\\d{8}(?!\\w)")),
                new PiiPattern("统一社会信用代码", Pattern.compile("(?<!\\w)\\d{2}[0-9A-Z]{8}[\\dA-Z]{6}[\\dA-Z](?![\\w])")),
                new PiiPattern("邮箱", Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")),
                new PiiPattern("银行卡号", Pattern.compile("(?<!\\d)(?:\\d[ -]?){16,19}(?!\\d)")),
                new PiiPattern("车牌号", Pattern.compile("(?<![A-Z0-9])[\\u4e00-\\u9fa5][A-Z][A-Z0-9]{5}(?![\\w])")),
                new PiiPattern("IP 地址", Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")),
                new PiiPattern("出生日期", Pattern.compile("(?:19|20)\\d{2}(?:[-/\\u5e74])(?:0[1-9]|1[0-2])(?:[-/\\u6708])(?:0[1-9]|[12]\\d|3[01])(?:\\u65e5)?"))
        );
    }
}