from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "政企大模型智能体安全服务"
    APP_VERSION: str = "1.0.0"
    
    LOG_LEVEL: str = "INFO"
    
    ZHIPU_API_KEY: str = "3f21bc1fa53d4d06b576b45611e9283d.CznNwmWNlVN2cbWT"
    
    MILVUS_HOST: str = "localhost"
    MILVUS_PORT: int = 19530
    MILVUS_COLLECTION: str = "knowledge_base"
    
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    
    ELASTICSEARCH_URL: str = "http://localhost:9200"
    ELASTICSEARCH_INDEX: str = "audit_logs"
    
    ATTACK_THRESHOLD_LOW: float = 0.3
    ATTACK_THRESHOLD_MEDIUM: float = 0.6
    ATTACK_THRESHOLD_HIGH: float = 0.85
    
    PLUGIN_SAFETY_THRESHOLD: int = 70
    
    MAX_CONTEXT_LENGTH: int = 8192
    MAX_INPUT_LENGTH: int = 4096


settings = Settings()