from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    # ======== 基础 ========
    APP_NAME: str = "政企大模型智能体安全服务"
    APP_VERSION: str = "1.0.0"
    LOG_LEVEL: str = "INFO"
    DEBUG: bool = False

    # ======== LLM ========
    ZHIPU_API_KEY: str = ""

    # ======== 服务器 ========
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    WORKERS: int = 1  # 生产环境建议 CPU 核心数

    # ======== CORS ========
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # ======== 限流 ========
    RATE_LIMIT_ENABLED: bool = False
    RATE_LIMIT_REQUESTS: int = 30    # 每分钟
    RATE_LIMIT_WINDOW: int = 60      # 秒

    # ======== 请求限制 ========
    MAX_REQUEST_SIZE_MB: int = 10    # 请求体上限
    MAX_FILE_SIZE_MB: int = 50       # 文件上传上限

    # ======== 基本鉴权(公网预览用) ========
    AUTH_ENABLED: bool = False
    AUTH_API_KEY: str = ""           # 简单 API Key,填写则启用

    # ======== 认证与会话（S1 认证加固）========
    AUTH_JWT_SECRET: str = ""              # JWT 签名密钥；生产务必在 .env 配置；留空则随机生成(重启后旧令牌失效)
    AUTH_TOKEN_TTL_SECONDS: int = 8 * 3600 # 访问令牌有效期（默认 8 小时）
    AUTH_LOGIN_MAX_FAILS: int = 5          # 连续登录失败上限
    AUTH_LOGIN_LOCK_SECONDS: int = 300     # 达到上限后的锁定时长（秒）

    # ======== 认证增强（S1 收尾）========
    AUTH_PASSWORD_MIN_LEN: int = 8             # 口令最小长度
    AUTH_PASSWORD_REQUIRE_COMPLEXITY: bool = True  # 需包含 大小写/数字/符号 中至少三类
    AUTH_MFA_ENABLED: bool = True              # 是否允许用户启用 MFA(TOTP)
    AUTH_MFA_ISSUER: str = "SafeAgent"         # TOTP 发行方（写入 otpauth URI）
    AUTH_MFA_TICKET_TTL: int = 300             # 登录二步验证临时票据有效期（秒）
    AUTH_SSO_TRUSTED_HEADER: str = ""          # 受信网关头名（如 X-Remote-User）；配置后启用 SSO 免密登录
    AUTH_SSO_SHARED_SECRET: str = ""           # SSO 网关共享密钥；配置后强制校验 X-SSO-Signature（防伪造受信头）
    AUTH_SSO_ALLOWED_IPS: str = ""              # SSO 来源 IP 白名单（逗号分隔，如 10.0.0.5,10.0.0.6）
    AUTH_MFA_SECRET_KEY: str = ""              # 敏感字段（MFA TOTP 密钥）加密密钥；留空则用 data/mfa_key.key

    # ======== 存储 ========
    SQLITE_PATH: str = ""            # 留空用默认 data/safeagent.db
    STORAGE_BACKEND: str = "sqlite"  # sqlite | postgres（生产建议 postgres）
    # PostgreSQL 连接（STORAGE_BACKEND=postgres 时生效；可只配 POSTGRES_DSN）
    POSTGRES_DSN: str = ""           # 形如 postgresql://user:pwd@host:5432/db；留空则用下方分项拼装
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "safeagent"
    POSTGRES_USER: str = "safeagent"
    POSTGRES_PASSWORD: str = ""

    # ======== 检测阈值 ========
    ATTACK_THRESHOLD_LOW: float = 0.3
    ATTACK_THRESHOLD_MEDIUM: float = 0.6
    ATTACK_THRESHOLD_HIGH: float = 0.85
    PLUGIN_SAFETY_THRESHOLD: int = 70
    MAX_CONTEXT_LENGTH: int = 8192
    MAX_INPUT_LENGTH: int = 4096

    # ======== 基础设施(预留) ========
    MILVUS_HOST: str = "localhost"
    MILVUS_PORT: int = 19530
    MILVUS_COLLECTION: str = "knowledge_base"
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    ELASTICSEARCH_URL: str = "http://localhost:9200"
    ELASTICSEARCH_INDEX: str = "audit_logs"


settings = Settings()
