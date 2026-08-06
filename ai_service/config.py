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

    # ======== 存储 ========
    SQLITE_PATH: str = ""            # 留空用默认 data/safeagent.db

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
