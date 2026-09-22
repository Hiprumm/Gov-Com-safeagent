package cn.safeagent.biz.common.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 健康检查 / 根路径探测（无需鉴权）。
 */
@RestController
public class HealthController {

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", true);
        out.put("service", "biz-service");
        out.put("status", "up");
        out.put("time", Instant.now().toString());
        return out;
    }
}