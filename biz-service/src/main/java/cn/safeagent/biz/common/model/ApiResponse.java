package cn.safeagent.biz.common.model;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 统一响应体，与 FastAPI 业务路由返回约定对齐：{success, message?, data?}。
 */
public final class ApiResponse {
    private ApiResponse() {}

    public static Map<String, Object> ok() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("success", true);
        return m;
    }

    public static Map<String, Object> ok(Object data) {
        Map<String, Object> m = ok();
        m.put("data", data);
        return m;
    }

    public static Map<String, Object> error(String message) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("success", false);
        m.put("error", message);
        return m;
    }
}