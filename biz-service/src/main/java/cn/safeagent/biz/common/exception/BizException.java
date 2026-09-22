package cn.safeagent.biz.common.exception;

/**
 * 业务错误：携带 HTTP 状态码与人类可读消息，由全局异常处理器转成统一响应体。
 */
public class BizException extends RuntimeException {
    private final int status;

    public BizException(int status, String message) {
        super(message);
        this.status = status;
    }

    public static BizException badRequest(String msg) { return new BizException(400, msg); }
    public static BizException unauthorized(String msg) { return new BizException(401, msg); }
    public static BizException forbidden(String msg) { return new BizException(403, msg); }
    public static BizException notFound(String msg) { return new BizException(404, msg); }
    public static BizException locked(String msg) { return new BizException(423, msg); }
    public static BizException unprocessable(String msg) { return new BizException(422, msg); }
    public static BizException server(String msg) { return new BizException(500, msg); }

    public int getStatus() { return status; }
}