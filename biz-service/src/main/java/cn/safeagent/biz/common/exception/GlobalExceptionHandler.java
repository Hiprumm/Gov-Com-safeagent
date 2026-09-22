package cn.safeagent.biz.common.exception;

import cn.safeagent.biz.common.model.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 全局异常 → 统一响应体。与 FastAPI 的错误结构保持一致：{success:false, error:msg}。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(BizException.class)
    public ResponseEntity<Map<String, Object>> handleBiz(BizException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", false);
        body.put("error", ex.getMessage());
        return ResponseEntity.status(ex.getStatus() > 0 ? ex.getStatus() : 500).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleOther(Exception ex) {
        log.error("未处理异常", ex);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", false);
        body.put("error", "服务内部错误：" + ex.getMessage());
        return ResponseEntity.status(500).body(body);
    }
}