package cn.safeagent.biz.common.security;

import cn.safeagent.biz.auth.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 统一鉴权拦截器：解析 X-Auth-Token，验签 + 校验 scope==access，实时读库校验账号 active。
 * 身份存于 request attribute【identity】，未登录/无效则置 attribute【identity_error】，
 * 由各 controller 按需放行（公开 / /api/auth/login 等无需鉴权）。
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    public AuthInterceptor(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    public static final String ATTR_IDENTITY = "identity";
    public static final String ATTR_ERROR = "identity_error";

    @Override
    public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object handler) {
        String token = req.getHeader("X-Auth-Token");
        if (token == null || token.isBlank()) {
            req.setAttribute(ATTR_ERROR, "未登录或登录已过期");
            return true;
        }
        Map<String, Object> payload = jwtService.decode(token);
        if (payload == null) {
            req.setAttribute(ATTR_ERROR, "登录已失效，请重新登录");
            return true;
        }
        if (!"access".equals(payload.get("scope"))) {
            req.setAttribute(ATTR_ERROR, "令牌类型错误");
            return true;
        }
        String username = payload.get("sub") instanceof String s ? s : null;
        if (username == null) {
            req.setAttribute(ATTR_ERROR, "登录已失效，请重新登录");
            return true;
        }
        // 实时读库：账号被禁用/删除则即刻失效
        Map<String, Object> user = userRepository.findIdentity(username);
        if (user == null || !"active".equals(user.get("status"))) {
            req.setAttribute(ATTR_ERROR, "账号不存在或已停用");
            return true;
        }
        Map<String, Object> identity = new LinkedHashMap<>();
        identity.put("username", username);
        identity.put("display_name", user.getOrDefault("display_name", username));
        identity.put("role", user.getOrDefault("role", "user"));
        identity.put("department", user.getOrDefault("department", ""));
        identity.put("position", user.getOrDefault("position", ""));
        req.setAttribute(ATTR_IDENTITY, identity);
        return true;
    }
}