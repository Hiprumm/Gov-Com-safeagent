package cn.safeagent.biz.notification;

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
 * 站内通知访问层（notifications 表归属：Spring Boot 写）。
 * 对齐 Python storage.list_notifications / count_unread / mark_read / clear。
 */
@Repository
public class NotificationRepository {

    private static final DateTimeFormatter TS = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final JdbcTemplate jdbc;
    private final NamedParameterJdbcTemplate named;

    public NotificationRepository(JdbcTemplate jdbc, NamedParameterJdbcTemplate named) {
        this.jdbc = jdbc;
        this.named = named;
    }

    public List<Map<String, Object>> list(int limit) {
        return jdbc.query("SELECT * FROM notifications ORDER BY id DESC LIMIT " + limit, Rows.userRow());
    }

    public long countUnread() {
        // PG 侧 read 为 BOOLEAN 严格类型（SQLite 中 TRUE/FALSE 等价 1/0），两边统一用布尔字面量
        Long n = jdbc.queryForObject("SELECT COUNT(*) FROM notifications WHERE read = FALSE", Long.class);
        return n == null ? 0 : n;
    }

    public void markRead(Integer notifId) {
        if (notifId == null) {
            jdbc.update("UPDATE notifications SET read = TRUE WHERE read = FALSE");
        } else {
            named.update("UPDATE notifications SET read = TRUE WHERE id = :id",
                    new MapSqlParameterSource("id", notifId));
        }
    }

    public void clear() {
        jdbc.update("DELETE FROM notifications");
    }
}