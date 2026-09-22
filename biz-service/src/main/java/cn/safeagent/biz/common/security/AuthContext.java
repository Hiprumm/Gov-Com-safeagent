package cn.safeagent.biz.common.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * 请求级身份访问助手：读取 AuthInterceptor 注入的 identity 与错误信息。
 */
@Component
public class AuthContext {

    /** 当前已认证身份（未登录返回 null） */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> current(HttpServletRequest req) {
        return (Map<String, Object>) req.getAttribute(AuthInterceptor.ATTR_IDENTITY);
    }

    /** 鉴权失败错误信息（未登录/无效 token），无则返回 null */
    public static String error(HttpServletRequest req) {
        Object e = req.getAttribute(AuthInterceptor.ATTR_ERROR);
        return e instanceof String s ? s : null;
    }
}