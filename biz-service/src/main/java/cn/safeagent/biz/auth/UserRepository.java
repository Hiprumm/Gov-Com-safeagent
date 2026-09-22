package cn.safeagent.biz.auth;

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
 * 共享库 sys_users 访问层（表归属：Spring Boot 写）。
 * 与 Python ai_service/storage.py 的 user 方法保持列级一致。
 */
@Repository
public class UserRepository {
    private static final DateTimeFormatter TS = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final JdbcTemplate jdbc;
    private final NamedParameterJdbcTemplate named;

    public UserRepository(JdbcTemplate jdbc, NamedParameterJdbcTemplate named) {
        this.jdbc = jdbc;
        this.named = named;
    }

    /** 登录校验所需的 password_hash/salt/status */
    public Map<String, Object> getPasswordRow(String username) {
        List<Map<String, Object>> rows = named.query(
                "SELECT username, password_hash, salt, display_name, role, department, position, status " +
                        "FROM sys_users WHERE username = :u", new MapSqlParameterSource("u", username), Rows.userRow());
        return rows.isEmpty() ? null : rows.get(0);
    }

    /** 实时身份（interceptor 用） */
    public Map<String, Object> findIdentity(String username) {
        List<Map<String, Object>> rows = named.query(
                "SELECT username, display_name, role, department, position, status FROM sys_users WHERE username = :u",
                new MapSqlParameterSource("u", username), Rows.userRow());
        return rows.isEmpty() ? null : rows.get(0);
    }

    public boolean userExists(String username) {
        Integer n = named.queryForObject("SELECT 1 FROM sys_users WHERE username = :u",
                new MapSqlParameterSource("u", username), Integer.class);
        return n != null;
    }

    public long countUsers() {
        Long n = jdbc.queryForObject("SELECT COUNT(*) FROM sys_users", Long.class);
        return n == null ? 0L : n;
    }

    public Map<String, Object> getUser(String username) {
        List<Map<String, Object>> rows = named.query("SELECT * FROM sys_users WHERE username = :u",
                new MapSqlParameterSource("u", username), Rows.userRow());
        return rows.isEmpty() ? null : rows.get(0);
    }

    /** MFA 状态（登录判定用） */
    public Map<String, Object> getUserMfa(String username) {
        List<Map<String, Object>> rows = named.query(
                "SELECT totp_secret, mfa_enabled FROM sys_users WHERE username = :u",
                new MapSqlParameterSource("u", username), Rows.userRow());
        return rows.isEmpty() ? Map.of("mfa_enabled", 0) : rows.get(0);
    }

    /** upsert_user，与 Python 的 ON CONFLICT DO UPDATE 一致 */
    public void upsertUser(String username, String passwordHash, String salt, String displayName,
                           String role, String department, String position, String status, String note) {
        String now = LocalDateTime.now().format(TS);
        named.update(
                "INSERT INTO sys_users (username, password_hash, salt, display_name, role, department, position, status, note, created_at, updated_at) " +
                        "VALUES (:username, :hash, :salt, :displayName, :role, :department, :position, :status, :note, :now, :now) " +
                        "ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, salt=excluded.salt, " +
                        "display_name=excluded.display_name, role=excluded.role, department=excluded.department, " +
                        "position=excluded.position, status=excluded.status, note=excluded.note, updated_at=excluded.updated_at",
                new MapSqlParameterSource()
                        .addValue("username", username).addValue("hash", passwordHash).addValue("salt", salt)
                        .addValue("displayName", displayName).addValue("role", role)
                        .addValue("department", department).addValue("position", position)
                        .addValue("status", status).addValue("note", note).addValue("now", now));
    }

    public List<Map<String, Object>> listUsers() {
        return named.query(
                "SELECT username, display_name, role, department, position, status, note, mfa_enabled, created_at, updated_at " +
                        "FROM sys_users ORDER BY role, username", Rows.userRow());
    }

    public int updateProfile(String username, String displayName, String role, String department,
                             String position, String status, String note) {
        var sets = new StringBuilder();
        var params = new MapSqlParameterSource("username", username).addValue("now", LocalDateTime.now().format(TS));
        boolean has = false;
        if (displayName != null) { sets.append("display_name = :displayName,"); params.addValue("displayName", displayName); has = true; }
        if (role != null) { sets.append("role = :role,"); params.addValue("role", role); has = true; }
        if (department != null) { sets.append("department = :department,"); params.addValue("department", department); has = true; }
        if (position != null) { sets.append("position = :position,"); params.addValue("position", position); has = true; }
        if (status != null) { sets.append("status = :status,"); params.addValue("status", status); has = true; }
        if (note != null) { sets.append("note = :note,"); params.addValue("note", note); has = true; }
        if (!has) return 0;
        sets.append("updated_at = :now");
        return named.update("UPDATE sys_users SET " + sets + " WHERE username = :username", params);
    }

    public int updatePassword(String username, String passwordHash, String salt) {
        return named.update(
                "UPDATE sys_users SET password_hash = :hash, salt = :salt, updated_at = :now WHERE username = :username",
                new MapSqlParameterSource("username", username).addValue("hash", passwordHash)
                        .addValue("salt", salt).addValue("now", LocalDateTime.now().format(TS)));
    }

    // ==================== 组织 / 部门 ====================

    public List<String> listDepartments() {
        return jdbc.queryForList("SELECT name FROM sys_departments ORDER BY created_at, name", String.class);
    }

    public boolean departmentExists(String name) {
        Integer n = named.queryForObject("SELECT 1 FROM sys_departments WHERE name = :n",
                new MapSqlParameterSource("n", name), Integer.class);
        return n != null;
    }

    public boolean addDepartment(String name) {
        if (departmentExists(name)) return false;
        return named.update(
                "INSERT INTO sys_departments (name, created_at) VALUES (:n, :now)",
                new MapSqlParameterSource("n", name)
                        .addValue("now", LocalDateTime.now().format(TS))) > 0;
    }

    /** 重命名部门并同步其下用户归属 */
    public boolean renameDepartment(String oldName, String newName) {
        if (!departmentExists(oldName) || departmentExists(newName)) return false;
        int a = named.update("UPDATE sys_departments SET name = :newN, created_at = created_at WHERE name = :oldN",
                new MapSqlParameterSource("newN", newName).addValue("oldN", oldName));
        named.update("UPDATE sys_users SET department = :newN WHERE department = :oldN",
                new MapSqlParameterSource("newN", newName).addValue("oldN", oldName));
        return a > 0;
    }

    /** 删除部门，其下用户归属置空 */
    public boolean removeDepartment(String name) {
        int a = named.update("DELETE FROM sys_departments WHERE name = :n",
                new MapSqlParameterSource("n", name));
        if (a > 0) {
            named.update("UPDATE sys_users SET department = '' WHERE department = :n",
                    new MapSqlParameterSource("n", name));
        }
        return a > 0;
    }

    public int deleteUser(String username) {
        return named.update("DELETE FROM sys_users WHERE username = :u",
                new MapSqlParameterSource("u", username));
    }
}