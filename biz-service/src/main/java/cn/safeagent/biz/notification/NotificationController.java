package cn.safeagent.biz.notification;

import cn.safeagent.biz.common.security.AuthContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 站内通知中心（登录即可；对齐 FastAPI routers/config.py 的 /api/notifications 读/已读/清空）。
 * 授权边界由轻量网关（login）把关，本层要求已登录。
 */
@RestController
@RequestMapping("/api/notifications")
public class NotificationController {

    private final NotificationRepository repo;

    public NotificationController(NotificationRepository repo) {
        this.repo = repo;
    }

    private Map<String, Object> requireLogin(HttpServletRequest req) {
        Map<String, Object> id = AuthContext.current(req);
        if (id == null) throw new cn.safeagent.biz.common.exception.BizException(401, "未登录");
        return id;
    }

    @GetMapping
    public Map<String, Object> list(HttpServletRequest req, @RequestParam(defaultValue = "50") int limit) {
        requireLogin(req);
        limit = Math.max(1, Math.min(limit, 200));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("list", repo.list(limit));
        out.put("unread", repo.countUnread());
        return out;
    }

    @PostMapping("/read")
    public Map<String, Object> read(HttpServletRequest req, @RequestBody(required = false) Map<String, Object> body) {
        requireLogin(req);
        Integer id = null;
        Object v = body == null ? null : body.get("id");
        if (v != null) id = (int) Math.max(0, Double.parseDouble(String.valueOf(v)));
        repo.markRead(id);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("unread", repo.countUnread());
        return out;
    }

    @PostMapping("/clear")
    public Map<String, Object> clear(HttpServletRequest req) {
        requireLogin(req);
        repo.clear();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        return out;
    }
}