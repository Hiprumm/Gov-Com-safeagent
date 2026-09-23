package cn.safeagent.biz.governance;

import cn.safeagent.biz.common.config.AppProperties;
import cn.safeagent.biz.common.config.JdbcConfig;
import cn.safeagent.biz.common.util.Rows;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * 治理域共享库访问层（表归属：Spring Boot 写）
 * 覆盖 emergency_controls / api_clients / api_call_logs / pipl_records。
 * 与 Python ai_service/governance.py + storage.py 保持列级与取值一致。
 */
@Repository
public class GovernanceRepository {

    private static final DateTimeFormatter TS = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final JdbcTemplate jdbc;
    private final NamedParameterJdbcTemplate named;
    private final AppProperties props;

    public GovernanceRepository(JdbcTemplate jdbc, NamedParameterJdbcTemplate named, AppProperties props) {
        this.jdbc = jdbc;
        this.named = named;
        this.props = props;
    }

    private String now() {
        return LocalDateTime.now().format(TS);
    }

    // ==================== 应急联动（emergency_controls） ====================

    /** 启用一个应急控制（同类型同目标先释放旧的再插入），返回新记录 id */
    public int addEmergencyControl(String type, String target, String operator, String reason) {
        named.update(
                "UPDATE emergency_controls SET enabled = 0, removed_at = :now " +
                        "WHERE control_type = :type AND target = :target AND enabled = 1",
                new MapSqlParameterSource("now", now()).addValue("type", type).addValue("target", target));
        GeneratedKeyHolder kh = new GeneratedKeyHolder();
        named.update(
                "INSERT INTO emergency_controls (control_type, target, enabled, operator, reason, created_at) " +
                        "VALUES (:type, :target, 1, :operator, :reason, :now)",
                new MapSqlParameterSource("type", type).addValue("target", target)
                        .addValue("operator", operator).addValue("reason", reason).addValue("now", now()),
                kh);
        java.util.Map<String, Object> keys = kh.getKeys();
        Object id = keys == null ? null : keys.values().stream().findFirst().orElse(null);
        return id == null ? 0 : ((Number) id).intValue();
    }

    public void releaseEmergencyControl(String type, String target) {
        named.update(
                "UPDATE emergency_controls SET enabled = 0, removed_at = :now " +
                        "WHERE control_type = :type AND target = :target AND enabled = 1",
                new MapSqlParameterSource("now", now()).addValue("type", type).addValue("target", target));
    }

    /** 生效中的控制（enabled=1） */
    public List<Map<String, Object>> activeEmergencyControls() {
        return named.query("SELECT * FROM emergency_controls WHERE enabled = 1 ORDER BY created_at DESC",
                new MapSqlParameterSource(), Rows.userRow());
    }

    public List<Map<String, Object>> emergencyHistory(int limit) {
        return jdbc.query("SELECT * FROM emergency_controls ORDER BY id DESC LIMIT " + limit, Rows.userRow());
    }

    // ==================== 开放生态（api_clients / api_call_logs） ====================

    public void upsertApiClient(String clientId, String name, String tokenHash, int enabled,
                                int rateLimit, int quota, String createdBy, String description) {
        MapSqlParameterSource params = new MapSqlParameterSource("cid", clientId).addValue("name", name).addValue("hash", tokenHash)
                .addValue("enabled", enabled).addValue("rate", rateLimit).addValue("quota", quota)
                .addValue("by", createdBy).addValue("desc", description).addValue("now", now());
        if (JdbcConfig.isPostgres(props)) {
            // PG 无 INSERT OR REPLACE：改写 upsert。used 不列即保持原值、created_at 重置为 now，
            // 与 SQLite 版 COALESCE(旧 used) + OR REPLACE 的最终效果一致
            named.update(
                    "INSERT INTO api_clients " +
                            "(client_id, name, token_hash, enabled, rate_limit, quota, used, created_by, description, created_at) " +
                            "VALUES (:cid, :name, :hash, :enabled, :rate, :quota, 0, :by, :desc, :now) " +
                            "ON CONFLICT(client_id) DO UPDATE SET name = excluded.name, token_hash = excluded.token_hash, " +
                            "enabled = excluded.enabled, rate_limit = excluded.rate_limit, quota = excluded.quota, " +
                            "created_by = excluded.created_by, description = excluded.description, created_at = excluded.created_at",
                    params);
        } else {
            named.update(
                    "INSERT OR REPLACE INTO api_clients " +
                            "(client_id, name, token_hash, enabled, rate_limit, quota, used, created_by, description, created_at) " +
                            "VALUES (:cid, :name, :hash, :enabled, :rate, :quota, " +
                            "COALESCE((SELECT used FROM api_clients WHERE client_id = :cid), 0), :by, :desc, :now)",
                    params);
        }
    }

    public List<Map<String, Object>> listApiClients() {
        return jdbc.query("SELECT * FROM api_clients ORDER BY created_at DESC", Rows.userRow());
    }

    public Map<String, Object> getApiClient(String clientId) {
        List<Map<String, Object>> rows = named.query("SELECT * FROM api_clients WHERE client_id = :cid",
                new MapSqlParameterSource("cid", clientId), Rows.userRow());
        return rows.isEmpty() ? null : rows.get(0);
    }

    public void deleteApiClient(String clientId) {
        named.update("DELETE FROM api_call_logs WHERE client_id = :cid",
                new MapSqlParameterSource("cid", clientId));
        named.update("DELETE FROM api_clients WHERE client_id = :cid",
                new MapSqlParameterSource("cid", clientId));
    }

    public void recordApiCall(String clientId, String name, String path, int status, String remoteIp) {
        named.update("UPDATE api_clients SET used = used + 1 WHERE client_id = :cid",
                new MapSqlParameterSource("cid", clientId));
        named.update(
                "INSERT INTO api_call_logs (client_id, name, path, status, remote_ip, created_at) " +
                        "VALUES (:cid, :name, :path, :status, :ip, :now)",
                new MapSqlParameterSource("cid", clientId).addValue("name", name).addValue("path", path)
                        .addValue("status", status).addValue("ip", remoteIp).addValue("now", now()));
    }

    public List<Map<String, Object>> listApiCallLogs(int limit) {
        return jdbc.query("SELECT * FROM api_call_logs ORDER BY id DESC LIMIT " + limit, Rows.userRow());
    }

    // ==================== PIPL 合规台账（pipl_records） ====================

    /** 同会话同类型同脱敏值去重；返回记录 id */
    public Long addPiplRecord(String sessionId, String username, String piiType, String masked, String source) {
        List<Map<String, Object>> dup = named.query(
                "SELECT id FROM pipl_records WHERE source = :src AND pii_type = :type AND masked_value = :masked " +
                        "AND session_id = :sid LIMIT 1",
                new MapSqlParameterSource("src", source).addValue("type", piiType)
                        .addValue("masked", masked).addValue("sid", sessionId == null ? "" : sessionId), Rows.userRow());
        if (!dup.isEmpty()) {
            Object id = dup.get(0).get("id");
            return id == null ? null : ((Number) id).longValue();
        }
        GeneratedKeyHolder kh = new GeneratedKeyHolder();
        named.update(
                "INSERT INTO pipl_records (session_id, username, pii_type, masked_value, source, created_at) " +
                        "VALUES (:sid, :u, :type, :masked, :src, :now)",
                new MapSqlParameterSource("sid", sessionId == null ? "" : sessionId).addValue("u", username == null ? "" : username)
                        .addValue("type", piiType).addValue("masked", masked).addValue("src", source).addValue("now", now()),
                kh);
        java.util.Map<String, Object> keys = kh.getKeys();
        Object key = keys == null ? null : keys.values().stream().findFirst().orElse(null);
        return key == null ? null : ((Number) key).longValue();
    }

    public List<Map<String, Object>> listPiplRecords(int limit) {
        return jdbc.query("SELECT * FROM pipl_records ORDER BY id DESC LIMIT " + limit, Rows.userRow());
    }

    public void updatePiplRecord(int recordId, String legalBasis, String assessment, String notedBy) {
        named.update(
                "UPDATE pipl_records SET legal_basis = :legal, assessment = :assess, noted_by = :by, updated_at = :now " +
                        "WHERE id = :id",
                new MapSqlParameterSource("legal", legalBasis).addValue("assess", assessment)
                        .addValue("by", notedBy).addValue("now", now()).addValue("id", recordId));
    }

    public Map<String, Object> piplStats() {
        Long total = jdbc.queryForObject("SELECT COUNT(*) FROM pipl_records", Long.class);
        Long pending = jdbc.queryForObject("SELECT COUNT(*) FROM pipl_records WHERE assessment = 'pending'", Long.class);
        List<Map<String, Object>> rows = jdbc.query(
                "SELECT pii_type, COUNT(*) AS c FROM pipl_records GROUP BY pii_type ORDER BY c DESC", Rows.userRow());
        Map<String, Object> byType = new java.util.LinkedHashMap<>();
        for (Map<String, Object> r : rows) {
            byType.put(String.valueOf(r.get("pii_type")), r.get("c"));
        }
        Map<String, Object> out = new java.util.LinkedHashMap<>();
        out.put("total", total == null ? 0 : total);
        out.put("pending", pending == null ? 0 : pending);
        out.put("by_type", byType);
        return out;
    }
}