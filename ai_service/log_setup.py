# -*- coding: utf-8 -*-
"""统一日志装配（阶段7：可观测性）

- LOG_FORMAT=json：单行 JSON 结构化日志（生产环境）
    {"ts": iso, "level": , "logger": , "msg": , "module": , ...extra}
- LOG_FORMAT=text：人读格式（开发环境）
    %(asctime)s [%(levelname)s] %(name)s: %(message)s

安全约束（SanitizeFilter，json/text 模式均生效）：
- 敏感字段脱敏：password/token/api_key/secret/authorization 的值替换为 ***REDACTED***
- 超长内容（>500 字符）截断为前 200 字符 + sha256 前 8 位指纹

幂等：重复调用 setup_logging 不会叠加 handler（仅允许更新日志级别）。
"""
import hashlib
import json
import logging
import re
import sys
from datetime import datetime

# ----------------------------------------------------------------------
# 敏感字段脱敏
# ----------------------------------------------------------------------
SENSITIVE_KEYS = ("password", "token", "api_key", "apikey", "secret", "authorization")
REDACTED = "***REDACTED***"
# 键值对形态：'password": "xxx' / token=xxx / api_key: xxx（含 JSON/URL/日志常见写法）
# 值候选排除 bareword "Bearer"（如 Authorization: Bearer xxx 交给下方专用正则，避免误吞 scheme 词后残留真 token）
_RE_KV = re.compile(
    r'(?i)("?(?:' + "|".join(SENSITIVE_KEYS) + r')"?\s*[:=]\s*)'
    r'("(?:[^"]*)"|\'(?:[^\']*)\'|(?!bearer\b)[^\s,;&}]+)'
)
# 头部形态：Authorization: Bearer xxx（值不含键名，单独处理）
_RE_BEARER = re.compile(r'(?i)(bearer\s+)[^\s"\']+')

# 超长内容截断阈值
MAX_CONTENT_LEN = 500
TRUNCATE_KEEP = 200


def sanitize_text(text: str) -> str:
    """先脱敏再截断（先脱敏可避免截断破坏敏感串的完整性）"""
    if not text:
        return text
    text = _RE_KV.sub(lambda m: m.group(1) + '"' + REDACTED + '"', text)
    text = _RE_BEARER.sub(lambda m: m.group(1) + REDACTED, text)
    if len(text) > MAX_CONTENT_LEN:
        digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:8]
        text = text[:TRUNCATE_KEEP] + f"...[truncated len={len(text)} sha256={digest}]"
    return text


class SanitizeFilter(logging.Filter):
    """脱敏 + 截断过滤器：就地改写 record.msg / record.args，永远放行"""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = sanitize_text(record.msg)
            args = record.args
            if isinstance(args, dict):
                record.args = {
                    k: sanitize_text(v) if isinstance(v, str) else v
                    for k, v in args.items()
                }
            elif isinstance(args, tuple):
                record.args = tuple(
                    sanitize_text(a) if isinstance(a, str) else a for a in args
                )
        except Exception:  # noqa: BLE001
            pass  # 过滤器自身异常绝不阻断日志输出
        return True


class JsonFormatter(logging.Formatter):
    """单行 JSON 日志格式器（含 extra 字段与异常栈）"""

    # LogRecord 标准属性：排除后剩余的即业务通过 extra={} 传入的字段
    _STD_ATTRS = frozenset((
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName", "message", "asctime",
    ))

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }
        # extra 字段：非标准属性直接并入（不可 JSON 序列化的转字符串）
        for key, value in record.__dict__.items():
            if key in self._STD_ATTRS or key.startswith("_"):
                continue
            if isinstance(value, (str, int, float, bool, type(None))):
                entry[key] = value
            else:
                entry[key] = str(value)
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False, default=str)


# ----------------------------------------------------------------------
# 装配
# ----------------------------------------------------------------------
_HANDLER_NAME = "safeagent-obs"
_configured = False


def setup_logging(log_format: str = "json", level: str = "INFO") -> None:
    """装配 root logger 与 uvicorn 日志（幂等：重复调用不叠加 handler）

    - log_format: json（生产，结构化单行）| text（开发，人读格式）
    - level: 日志级别（settings.LOG_LEVEL）
    """
    global _configured
    root = logging.getLogger()
    root.setLevel((level or "INFO").upper())

    if _configured:
        return  # 幂等：重复调用仅更新级别，不重复加 handler

    handler = logging.StreamHandler(sys.stdout)
    handler.set_name(_HANDLER_NAME)  # 幂等标记
    handler.addFilter(SanitizeFilter())
    if (log_format or "json").lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
    root.addHandler(handler)

    # uvicorn 日志收敛到 root 统一输出：清自带 handler、开 propagate，避免双写。
    # 注：uvicorn.run()/CLI 启动时会以默认 log_config 重建自身 handler（propagate
    # 随之被覆盖）；若需 access log 也走本配置，启动时传 log_config=None。
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True

    _configured = True
