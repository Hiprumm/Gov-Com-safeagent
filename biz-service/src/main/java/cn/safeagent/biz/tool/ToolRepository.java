package cn.safeagent.biz.tool;

import cn.safeagent.biz.common.util.Rows;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import jakarta.annotation.PostConstruct;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * 工具管控开关共享表访问层（表 tool_management 归属 Spring Boot 写）。
 * 持久化「工具管控总开关」，实现跨 worker / 跨服务一致（替换 FastAPI 原内存变量 tool_management_enabled）。
 */
@Repository
public class ToolRepository {

    private static final DateTimeFormatter TS = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    private static final String ENABLED_KEY = "enabled";

    private final NamedParameterJdbcTemplate named;

    public ToolRepository(NamedParameterJdbcTemplate named) {
        this.named = named;
    }

    /** 兜底建表（幂等）：表由 ai_service/storage.py 的 _init_db 统一创建，此处确保独立启动时存在。 */
    @PostConstruct
    public void ensureTable() {
        named.getJdbcTemplate().execute(
                "CREATE TABLE IF NOT EXISTS tool_management (" +
                        "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                        "key TEXT UNIQUE," +
                        "value TEXT," +
                        "updated_at TEXT)");
    }

    private String now() {
        return LocalDateTime.now().format(TS);
    }

    /** 读取工具管控开关，缺省为开启（true） */
    public boolean isEnabled() {
        List<Map<String, Object>> rows = named.query(
                "SELECT value FROM tool_management WHERE key = :key",
                new MapSqlParameterSource("key", ENABLED_KEY), Rows.userRow());
        if (rows.isEmpty()) return true;
        Object v = rows.get(0).get("value");
        return v == null || Boolean.parseBoolean(String.valueOf(v));
    }

    /** 写入工具管控开关 */
    public void setEnabled(boolean enabled) {
        named.update(
                "INSERT INTO tool_management (key, value, updated_at) VALUES (:key, :val, :now) " +
                        "ON CONFLICT(key) DO UPDATE SET value = :val, updated_at = :now",
                new MapSqlParameterSource("key", ENABLED_KEY).addValue("val", String.valueOf(enabled)).addValue("now", now()));
    }
}