package cn.safeagent.biz.approval;

import cn.safeagent.biz.common.util.Rows;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * 审批域共享库访问层（表 approval_requests 归属 Spring Boot 写）。
 * 与 Python ai_service/storage.py 的 approve/approval 方法与列级保持一致。
 * 注意：审批单【创建】（gov_agent 工具执行前 create_request）仍在 AI 进程内完成；
 * 本层只负责管理端点（查询 pending/history、审批通过/驳回、状态查询）的人工动作写库。
 */
@Repository
public class ApprovalRepository {

    private static final DateTimeFormatter TS = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final JdbcTemplate jdbc;
    private final NamedParameterJdbcTemplate named;

    public ApprovalRepository(JdbcTemplate jdbc, NamedParameterJdbcTemplate named) {
        this.jdbc = jdbc;
        this.named = named;
    }

    private String now() {
        return LocalDateTime.now().format(TS);
    }

    /** 待审批列表（status=pending），按创建时间倒序 */
    public List<Map<String, Object>> listPending() {
        return jdbc.query("SELECT * FROM approval_requests WHERE status = 'pending' ORDER BY created_at DESC", Rows.userRow());
    }

    /** 最近审批记录（全部状态），按更新时间倒序 */
    public List<Map<String, Object>> listRecent(int limit) {
        return jdbc.query("SELECT * FROM approval_requests ORDER BY updated_at DESC LIMIT " + Math.max(1, Math.min(limit, 200)), Rows.userRow());
    }

    public Map<String, Object> get(String requestId) {
        List<Map<String, Object>> rows = named.query("SELECT * FROM approval_requests WHERE request_id = :id",
                new MapSqlParameterSource("id", requestId), Rows.userRow());
        return rows.isEmpty() ? null : rows.get(0);
    }

    /**
     * 审批通过：仅当当前 status=pending 时生效，避免覆盖已处理单。
     * @return 是否真正发生更新
     */
    public boolean approve(String requestId, String approverId, String approverRole, String reason) {
        int n = named.update(
                "UPDATE approval_requests SET status = 'approved', approver_id = :by, approver_role = :role, " +
                        "reason = :reason, updated_at = :now WHERE request_id = :id AND status = 'pending'",
                new MapSqlParameterSource("by", approverId).addValue("role", approverRole)
                        .addValue("reason", reason == null ? "" : reason)
                        .addValue("now", now()).addValue("id", requestId));
        return n > 0;
    }

    /** 驳回：仅当 status=pending 时生效 */
    public boolean reject(String requestId, String approverId, String reason) {
        int n = named.update(
                "UPDATE approval_requests SET status = 'rejected', approver_id = :by, " +
                        "reason = :reason, updated_at = :now WHERE request_id = :id AND status = 'pending'",
                new MapSqlParameterSource("by", approverId).addValue("reason", reason == null ? "" : reason)
                        .addValue("now", now()).addValue("id", requestId));
        return n > 0;
    }
}