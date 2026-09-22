package cn.safeagent.biz.common.util;

import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 通用工具：把 ResultSet 行转成大小写不敏感 Map，便于与 Python storage 返回的 dict 对齐。
 */
public final class Rows {
    private Rows() {}

    /** 返回通用列映射（username/display_name/role/department/position/status/note/...） */
    public static RowMapper<Map<String, Object>> userRow() {
        return (rs, i) -> mapFrom(rs);
    }

    public static LinkedHashMap<String, Object> mapFrom(ResultSet rs) throws SQLException {
        var cols = rs.getMetaData();
        var m = new LinkedHashMap<String, Object>();
        for (int c = 1; c <= cols.getColumnCount(); c++) {
            String name = cols.getColumnLabel(c);
            Object val = rs.getObject(c);
            m.put(name, val != null ? val : null);
        }
        return m;
    }
}