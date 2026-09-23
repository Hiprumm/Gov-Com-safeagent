from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    # ======== 基础 ========
    APP_NAME: str = "政企大模型智能体安全服务"
    APP_VERSION: str = "1.0.0"
    LOG_LEVEL: str = "INFO"
    DEBUG: bool = False

    # ======== 运行环境（生产级改造）========
    # development=演示/开发模式；production=生产模式（强制鉴权、禁沙箱本地降级、禁默认口令）
    ENV: str = "development"

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
    RATE_LIMIT_IP_REQUESTS: int = 120  # IP 维度每分钟上限（网关双层限流：用户+IP 叠加检查）

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
    # 审计链签名密钥（生产级改造：优先环境变量注入，禁止依赖 data/ 落盘文件）
    GRADED_HMAC_KEY: str = ""                  # 分级审计 HMAC 签名密钥（hex，openssl rand -hex 32）
    ZKP_PROVING_KEY: str = ""                  # ZKP 证明密钥（hex）

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

    # ======== 优化闭环(收敛为默认只读) ========
    # 检测调优闭环的写端点(反馈标注/自动调优/版本应用/样例扩充等)无前端消费，
    # 默认关闭，仅保留只读端点；需要时置 ENABLE_OPTIMIZATION_WRITE=true 开启。
    ENABLE_OPTIMIZATION_WRITE: bool = False

    # ======== 基础设施(预留) ========
    MILVUS_HOST: str = "localhost"
    MILVUS_PORT: int = 19530
    MILVUS_COLLECTION: str = "knowledge_base"
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    ELASTICSEARCH_URL: str = "http://localhost:9200"
    ELASTICSEARCH_INDEX: str = "audit_logs"

    # ======== 工具沙箱（生产级改造：默认拒绝本地降级）========
    # 0=沙箱不可用时直接拒绝执行（默认，生产强制）；1=允许降级本地受限执行（仅开发调试）
    SANDBOX_ALLOW_LOCAL_FALLBACK: int = 0
    # 允许出站的工具白名单（逗号分隔工具名，默认空=deny-all；沙箱内其余工具一律无网络）
    TOOL_NETWORK_WHITELIST: str = ""

    # ======== 检测流水线（生产级改造）========
    # LLM 语义仲裁超时（毫秒）。改进清单理想值 500ms 仅适用规则预筛场景；
    # 语义仲裁需完整分类输出，默认 2000ms，可按供应商实测调整
    LLM_ARBITER_TIMEOUT_MS: int = 2000

    # ======== 审计链（生产级改造）========
    # 多 TSA 端点（逗号分隔，主备依次尝试，全部失败才本地时间戳降级）
    TSA_ENDPOINTS: str = ""
    # 审计日志保留天数（备份脚本保留周期对齐）
    AUDIT_RETENTION_DAYS: int = 180

    # ======== 可观测性（生产级改造）========
    LOG_FORMAT: str = "json"          # json=结构化日志（生产）；text=控制台可读（开发）
    METRICS_ENABLED: bool = True      # 暴露 /metrics Prometheus 指标

    def is_production(self) -> bool:
        return str(self.ENV).strip().lower() == "production"

    def validate_production(self) -> None:
        """生产模式启动校验：不满足生产安全基线时直接抛错拒绝启动。

        校验项（对齐 docs/改进.md P0-2）：
        - AUTH_ENABLED 必须开启
        - 沙箱本地降级必须关闭（显式设 1 视为配置冲突）
        - JWT / MFA / 审计链密钥必须显式注入（禁止运行时随机生成导致多实例不一致）
        """
        if not self.is_production():
            return
        problems = []
        if not self.AUTH_ENABLED:
            problems.append("AUTH_ENABLED 必须为 true（生产强制鉴权）")
        if self.SANDBOX_ALLOW_LOCAL_FALLBACK not in (0, "0"):
            problems.append("SANDBOX_ALLOW_LOCAL_FALLBACK 必须为 0（生产禁止沙箱本地降级）")
        if not self.AUTH_JWT_SECRET:
            problems.append("AUTH_JWT_SECRET 未配置（生产禁止运行时随机生成，多实例会令牌互不认）")
        if not self.GRADED_HMAC_KEY:
            problems.append("GRADED_HMAC_KEY 未配置（审计链签名密钥须由环境变量/KMS 注入）")
        if not self.ZKP_PROVING_KEY:
            problems.append("ZKP_PROVING_KEY 未配置（审计链 ZKP 密钥须由环境变量/KMS 注入）")
        if self.STORAGE_BACKEND != "postgres":
            print("[CONFIG][WARN] 生产环境建议 STORAGE_BACKEND=postgres（SQLite 仅限本地开发）")
        if problems:
            raise RuntimeError(
                "生产模式（ENV=production）启动校验失败，拒绝启动：\n  - "
                + "\n  - ".join(problems)
                + "\n请在 .env 或环境变量中补齐上述配置后重试。"
            )


settings = Settings()
