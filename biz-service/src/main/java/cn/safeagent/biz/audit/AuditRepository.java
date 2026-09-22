package cn.safeagent.biz.audit;

import cn.safeagent.biz.common.util.Rows;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 审计域共享库访问层（audit_logs 表归属：Spring Boot 写）。
 * 读取方法对齐 Python audit_logger + storage 的列解析（action_details 等 JSON 字段反序列化）。
 */
@Repository
public class AuditRepository {

    private static final DateTimeFormatter TS = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final JdbcTemplate jdbc;
    private final NamedParameterJdbcTemplate named;

    public AuditRepository(JdbcTemplate jdbc, NamedParameterJdbcTemplate named) {
        this.jdbc = jdbc;
        this.named = named;
    }

    private String now() {
        return LocalDateTime.now().format(TS);
    }

    /** 解析 action_details / extra_data 等 JSON 字符串列（无法解析则原样返回） */
    @SuppressWarnings("unchecked")
    public Map<String, Object> parseRow(Map<String, Object> row) {
        Map<String, Object> d = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : row.entrySet()) {
            Object v = e.getValue();
            String k = e.getKey();
            if (v instanceof String s && (k.equals("action_details") || k.equals("detection_result")
                    || k.equals("tool_call_result") || k.equals("tool_args") || k.equals("extra_data"))) {
                Object parsed = tryJson(s);
                if (parsed != null) { d.put(k, parsed); continue; }
            }
            if (k.equals("is_blocked") && v instanceof Number n) {
                d.put(k, n.intValue() != 0);
                continue;
            }
            d.put(k, v);
        }
        return d;
    }

    private static Object tryJson(String s) {
        try { return new com.fasterxml.jackson.databind.ObjectMapper().readValue(s, Object.class); }
        catch (Exception e) { return null; }
    }

    public List<Map<String, Object>> recent(int limit) {
        return jdbc.query("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT " + limit, Rows.userRow());
    }

    public List<Map<String, Object>> page(int page, int pageSize) {
        int offset = Math.max(0, (page - 1) * pageSize);
        return jdbc.query("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT " + pageSize + " OFFSET " + offset, Rows.userRow());
    }

    public long count() {
        Long n = jdbc.queryForObject("SELECT COUNT(*) FROM audit_logs", Long.class);
        return n == null ? 0 : n;
    }

    public Map<String, Object> byId(String logId) {
        List<Map<String, Object>> rows = named.query("SELECT * FROM audit_logs WHERE log_id = :id",
                new MapSqlParameterSource("id", logId), Rows.userRow());
        return rows.isEmpty() ? null : parseRow(rows.get(0));
    }

    public List<Map<String, Object>> search(String userId, String agentId, String riskLevel,
                                            String actionType, Boolean isBlocked, int limit) {
        StringBuilder q = new StringBuilder("SELECT * FROM audit_logs WHERE 1=1");
        var params = new MapSqlParameterSource();
        if (userId != null && !userId.isBlank()) { q.append(" AND user_id = :userId"); params.addValue("userId", userId); }
        if (agentId != null && !agentId.isBlank()) { q.append(" AND agent_id = :agentId"); params.addValue("agentId", agentId); }
        if (riskLevel != null && !riskLevel.isBlank()) { q.append(" AND risk_level = :risk"); params.addValue("risk", riskLevel); }
        if (actionType != null && !actionType.isBlank()) { q.append(" AND action_type = :act"); params.addValue("act", actionType); }
        if (isBlocked != null) { q.append(" AND is_blocked = :blocked"); params.addValue("blocked", isBlocked ? 1 : 0); }
        q.append(" ORDER BY timestamp DESC LIMIT ").append(limit);
        List<Map<String, Object>> rows = named.query(q.toString(), params, Rows.userRow());
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> r : rows) out.add(parseRow(r));
        return out;
    }

    /** 治理动作落审计（表归属 Spring 写） */
    public void append(String actionType, String operator, String riskLevel, Map<String, Object> details) {
        String logId = UUID.randomUUID().toString();
        String ts = now();
        String detailsJson = details == null ? "{}" : toJson(details);
        final MapSqlParameterSource p = new MapSqlParameterSource()
                .addValue("log_id", logId)
                .addValue("ts", ts)
                .addValue("user_id", operator == null || operator.isBlank() ? "system" : operator)
                .addValue("user_role", "admin")
                .addValue("agent_id", "governance")
                .addValue("action_type", actionType)
                .addValue("details", detailsJson)
                .addValue("risk_level", riskLevel == null ? "high" : riskLevel)
                .addValue("blocked", 0);
        String sql = "INSERT INTO audit_logs (log_id, timestamp, user_id, user_role, agent_id, action_type, " +
                "action_details, risk_level, is_blocked) VALUES (:log_id, :ts, :user_id, :user_role, :agent_id, " +
                ":action_type, :details, :risk_level, :blocked)";
        jdbc.update((java.sql.Connection conn) -> {
            var ps = conn.prepareStatement(sql, new String[]{"log_id"});
            ps.setString(1, logId);
            ps.setString(2, ts);
            ps.setString(3, operator == null || operator.isBlank() ? "system" : operator);
            ps.setString(4, "admin");
            ps.setString(5, "governance");
            ps.setString(6, actionType);
            ps.setString(7, detailsJson);
            ps.setString(8, riskLevel == null ? "high" : riskLevel);
            ps.setInt(9, 0);
            return ps;
        });
    }

    private static String toJson(Object o) {
        try { return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(o); }
        catch (Exception e) { return "{}"; }
    }
}