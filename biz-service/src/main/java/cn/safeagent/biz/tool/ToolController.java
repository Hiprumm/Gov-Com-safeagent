package cn.safeagent.biz.tool;

import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 工具管控开关（表 tool_management 归属 Spring）。
 * 对齐 FastAPI ai_service/routers/security.py 的 /api/security/tool_management/status|toggle，
 * 但由内存变量改为共享库持久化，跨 worker/服务一致。
 * 授权边界由轻量网关把关（status→tools.view，toggle→tools.manage）。
 */
@RestController
@RequestMapping("/api/security/tool_management")
public class ToolController {

    private final ToolRepository repo;

    public ToolController(ToolRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", repo.isEnabled());
        return out;
    }

    @PostMapping("/toggle")
    public Map<String, Object> toggle(@RequestBody(required = false) Map<String, Object> body) {
        boolean next;
        if (body != null && body.containsKey("enabled")) {
            next = Boolean.TRUE.equals(body.get("enabled"));
        } else {
            next = !repo.isEnabled();
        }
        repo.setEnabled(next);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", repo.isEnabled());
        return out;
    }
}