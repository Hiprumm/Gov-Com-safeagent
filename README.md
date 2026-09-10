# 政企大模型智能体安全系统 — SafeAgent v4.0

面向政企场景的大模型智能体安全检测与防护系统，提供输入检测、插件安全、知识库投毒防御、工具执行沙箱和审批管理等核心能力。

---

## 目录

- [1. 项目概览](#1-项目概览)
- [2. 快速启动](#2-快速启动)
  - [2.1 Docker 一键部署（推荐）](#21-docker-一键部署推荐)
  - [2.2 本地开发模式](#22-本地开发模式)
  - [2.3 手动部署](#23-手动部署)
- [3. 系统架构](#3-系统架构)
- [4. 功能模块](#4-功能模块)
- [5. 配置说明](#5-配置说明)
- [6. 评测与报告](#6-评测与报告)
- [7. 项目结构](#7-项目结构)
- [8. 常见问题](#8-常见问题)

---

## 1. 项目概览

### 核心指标

| 指标 | 数值 |
|------|------|
| 检测流水线 | **六层**（Unicode规范化 → 高级解码 → 规则/AI/向量四层混合检测 → LLM语义仲裁 → 记忆安全检测） |
| 检测基线（335 样本） | 准确率 **98.5%** / 精确率 **99.6%** / F1 **99.1%** / 漏报率 **1.5%** / 误报率 **1.7%** |
| 攻击样例库 | **335 条**（275 攻击 + 60 正常），覆盖 27 类攻击类型、多源输入标注 |
| 攻击类型覆盖 | **27 大类**（提示注入/间接注入/越狱/命令注入/SQL注入/数据泄露/数据外传链/内容注入/数据投毒/记忆投毒/技能篡改/工具描述符投毒/MCP投毒/组合攻击/供应链投毒等） |
| 纵深防御 | 检测 → 能力令牌默认deny → operation_guard动作守卫+Plan IR序列评估 → 分级签名审计链（HMAC+Agent签名+ZKP+批量TSA） |
| 红队验证 | 检测全失效场景下高危操作拦截 **30/30** |
| 审计链性能 | 分级签名+批量TSA 加速 **9.95x**（TSA 网络请求 ↓90%） |
| 生态适配 | pip SDK（LangChain/LlamaIndex/Dify 适配器）+ 网关中间件，集成测试 31/31 |

### 技术栈

| 层级 | 技术 |
|------|------|
| 后端 | Python 3.12 + FastAPI + LangGraph + SQLite |
| 前端 | Vue 3 + TypeScript + Vite + Tailwind CSS + ECharts |
| AI 模型 | 智谱 GLM-4-Flash（语义分类） |
| 部署 | Docker + Docker Compose + Nginx |
| 实时通信 | WebSocket（替代 HTTP 轮询） |

---

## 2. 快速启动

### 环境要求

| 软件 | 最低版本 | 说明 |
|------|---------|------|
| Docker | 20.10+ | Docker Compose 需 V2 |
| Node.js | 18+ | 前端构建（Docker部署自动处理） |
| Python | 3.12+ | 本地开发模式需要 |

### 2.1 Docker 一键部署（推荐）

```bash
# === Windows ===
cd deploy
start_production.bat

# === Linux / macOS ===
cd deploy
chmod +x start.sh
./start.sh
```

启动后访问：
- **网页前端**：http://localhost
- **API 文档**：http://localhost:8080/docs
- **健康检查**：http://localhost:8080/api/health
- **WebSocket 状态**：http://localhost:8080/api/ws/status

**常用命令**：

```bash
# 停止服务
./start.sh --stop          # Linux/Mac
start_production.bat stop  # Windows

# 查看日志
docker compose -f deploy/docker-compose.yml logs -f

# 清理容器和镜像
./start.sh --clean
```

### 2.2 本地开发模式

```bash
# === 后端 ===
cd ai_service
cp .env.example .env          # 编辑 .env 填写 ZHIPU_API_KEY
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload

# === 前端（新终端） ===
cd frontend
npm install
npm run dev                    # http://localhost:5173
```

开发模式下前端自动代理 API 到 `localhost:8080`（见 `frontend/vite.config.ts`）。

### 2.3 手动部署

```bash
# 1. 构建前端
cd frontend
npm install && npm run build

# 2. 配置环境
cd ../ai_service
cp .env.example .env
# 编辑 .env 填写 ZHIPU_API_KEY

# 3. 启动后端
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8080 --workers 2

# 4. 配置 Nginx（可选）
# 将 deploy/nginx.conf 放到 /etc/nginx/sites-available/
# 将 frontend/dist/ 部署到静态文件目录
```

---

## 3. 系统架构

```
┌──────────────────────────────────────────────────────────┐
│                    用户浏览器 (:80)                        │
│              Vue 3 SPA + WebSocket Client                 │
└──────────────┬──────────────────────────────┬────────────┘
               │ HTTP / WebSocket               │
┌──────────────▼──────────────────────────────▼────────────┐
│                    Nginx 反向代理                          │
│          /api/* → AI Service    /ws/* → WebSocket        │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────┐
│              AI Service (FastAPI :8080)                   │
│                                                           │
│  ┌─────────────────────────────────────────────────┐     │
│  │              检测流水线 (5层)                      │     │
│  │                                                    │     │
│  │  第0层   Unicode规范化 (NFKC + 全角半角 + 同形字) │     │
│  │  第0.5层 高级解码 (Base64 + 转义 + 去空格SQL)    │     │
│  │  第1层   规则引擎 (150+ 正则 + 关键词)            │     │
│  │  第2层   AI语义检测 (3层: 高/中/模式匹配)         │     │
│  │  第3层   向量投毒检测 (知识库基线相似度)           │     │
│  │  第4层   LLM语义仲裁 (智谱GLM-4-Flash)            │     │
│  └─────────────────────────────────────────────────┘     │
│                                                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │ 输入检测 │ │ 插件扫描 │ │ 审批引擎 │ │ 工具沙箱 │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │知识库防御│ │对抗测试  │ │审计日志  │ │评测报告  │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
│                                                           │
│       SQLite (audit_logs / approvals / sessions)          │
└───────────────────────────────────────────────────────────┘
```

---

## 4. 功能模块

### 4.1 输入安全检测

实时检测用户输入中的攻击意图，支持 8 种攻击类型识别和风险等级评估（NONE / LOW / MEDIUM / HIGH / CRITICAL）。

**5 层检测流水线**：

| 层 | 名称 | 功能 |
|----|------|------|
| 0 | Unicode 规范化 | NFKC、全角→半角、同形异义字还原、零宽字符移除 |
| 0.5 | 高级解码 | Base64 单/双重解码、Unicode 转义、去空格 SQL 重建、去拼接 SQL |
| 1 | 规则引擎 | 150+ 正则模式 + 高/中风险关键词匹配 |
| 2 | AI 检测器 | 3 层语义检测：高/中置信度关键词 + 语义模式匹配 |
| 3 | 向量投毒检测 | 知识库基线相似度 + 投毒模式 + 异常内容识别 |
| 4 | LLM 语义仲裁 | 智谱 GLM-4-Flash，检测间接攻击；API 不可用时降级至本地启发式规则 |

**代码审查上下文差分降权**：规则引擎 -0.65，AI/向量 -0.30，置信度 ≥0.55 的强信号保留。

### 4.2 插件安全扫描

- npm/PyPI 依赖安全分析
- 恶意包检测（后门代码/权限提升/数据窃取）
- 依赖版本漏洞扫描

### 4.3 审批管理

- 多级审批矩阵：LOW 自动通过，MEDIUM→manager，HIGH→admin，CRITICAL→super_admin
- WebSocket 实时推送审批状态变更（替代 3s HTTP 轮询）
- 审批历史追溯

### 4.4 工具执行沙箱

- Docker 隔离执行环境（CPU 0.5 核 / 内存 256MB / 超时 30s）
- 只读根文件系统 + 网络白名单
- 本地模拟回退（Docker 不可用时自动降级）
- 工具列表：read_file / search_knowledge / send_email / query_db

### 4.5 知识库投毒防御

- PDF/文本内容相似度分析
- 异常模式识别
- 外部 URL 关联检测

### 4.6 对抗鲁棒性测试

10 种变异策略，一键生成绕过多层检测的对抗样本：

| # | 策略 | 说明 |
|---|------|------|
| 1 | 全角替换 | 半角→全角 Unicode 映射 |
| 2 | 同形异义 | Cyrillic 字符替换 Latin |
| 3 | 零宽字符 | ZWSP 插入打散关键词 |
| 4 | 空格变体 | 非标准空格替换 |
| 5 | 大小写混淆 | 随机大小写/交替大小写 |
| 6 | 编码绕过 | URL 百分号编码 |
| 7 | 分隔符插入 | 关键词中插入无害字符 |
| 8 | Base64 编码 | 完整/部分 Base64 编码 |
| 9 | 实体编码 | HTML/Unicode/JSON 实体 |
| 10 | 多语言混合 | 中英日韩文字混入 |

### 4.7 审计与评测

- 操作审计日志完整记录
- CSV/JSON 导出（按风险等级/用户/操作类型筛选）
- 攻击模式统计分析
- 评测报告自动生成（Markdown + HTML 可打印 PDF）

---

## 5. 配置说明

### 5.1 环境变量

复制 `ai_service/.env.example` 为 `ai_service/.env`：

```bash
# === 必填 ===
ZHIPU_API_KEY=your_zhipu_api_key_here   # 智谱 AI API Key（或改用内网 OpenAI 兼容端点）

# === 认证与会话（生产务必配置） ===
AUTH_JWT_SECRET=                        # 令牌签名密钥；留空会持久化到 data/jwt_secret.key（多实例必须显式配置同一值）
AUTH_TOKEN_TTL_SECONDS=28800            # 访问令牌有效期（秒），默认 8 小时
AUTH_LOGIN_MAX_FAILS=5                  # 连续登录失败上限
AUTH_LOGIN_LOCK_SECONDS=300             # 达到上限后的锁定时长（秒）
AUTH_PASSWORD_MIN_LEN=8                 # 口令最小长度
AUTH_PASSWORD_REQUIRE_COMPLEXITY=true   # 需含大小写/数字/符号中至少三类
AUTH_MFA_ENABLED=true                   # 是否允许用户启用 MFA(TOTP)
AUTH_MFA_SECRET_KEY=                   # MFA TOTP 密钥加密密钥；留空用 data/mfa_key.key（多实例需一致）
AUTH_SSO_TRUSTED_HEADER=                # 受信网关头名（如 X-Remote-User）；配置后启用 SSO 免密登录
AUTH_SSO_SHARED_SECRET=                 # SSO 网关共享密钥；配置后强制校验 X-SSO-Signature（防伪造受信头）
AUTH_SSO_ALLOWED_IPS=                   # SSO 来源 IP 白名单（逗号分隔，如 10.0.0.5,10.0.0.6）

# === 服务间鉴权（生产建议启用） ===
AUTH_ENABLED=false                      # 置 true 后所有接口需 X-API-Key
AUTH_API_KEY=your_custom_api_key        # 服务间密钥（SDK/网关调用方使用）

# === 存储 ===
STORAGE_BACKEND=sqlite                  # sqlite（默认）| postgres（生产推荐）
POSTGRES_DSN=                           # 形如 postgresql://user:pwd@host:5432/db；留空用下方分项
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=safeagent
POSTGRES_USER=safeagent
POSTGRES_PASSWORD=

# === 限流与请求体 ===
RATE_LIMIT_ENABLED=false
RATE_LIMIT_REQUESTS=30                  # 每分钟请求数
RATE_LIMIT_WINDOW=60                    # 时间窗口（秒）
MAX_REQUEST_SIZE_MB=50

# === 其他 ===
HOST=0.0.0.0
PORT=8080
LOG_LEVEL=INFO
DEBUG=false
ALLOWED_ORIGINS=http://localhost:5173   # CORS 白名单（逗号分隔，生产收敛为实际域名）
AUDIT_RETENTION_DAYS=180                # 审计日志留存天数
```

> **生产上线必读**：[部署与安全加固指南.md](部署与安全加固指南.md)（配置基线、鉴权模型、已知限制、上线检查清单）。

### 5.2 推荐部署拓扑

仓库**不含** Docker 编排文件，生产建议按下述拓扑自行编排（示例）：

| 组件 | 端口 | 说明 |
|------|------|------|
| 反向代理（Nginx 等） | 443/80 | TLS 终止 + 静态托管前端 `frontend/dist` + 转发 `/api` `/ai` `/ws` |
| AI Service | 8080 | FastAPI 后端（统一鉴权 / 检测 / 治理 / 审计） |
| PostgreSQL | 5432 | 生产存储后端（`STORAGE_BACKEND=postgres`）；SQLite 仅单机/演示 |

> 反向代理需透传 `X-Auth-Token`、`X-API-Key` 与来源 IP，并放通 WebSocket 升级。

---

## 6. 评测与报告

### 运行评测

```bash
cd ai_service/audit
python run_evaluation.py
```

评测将逐条检测 `attack_samples.json` 中全部 210 条样本并生成 `evaluation_report.json`。

### 生成报告

```bash
cd ai_service/audit
python generate_report.py           # 仅 Markdown
python generate_report.py --pdf     # Markdown + HTML（浏览器打印 PDF）
```

### 复现攻击

```bash
# 在 Swagger UI 或 curl 中调用
POST /api/replay/all                # 批量复现所有攻击样本
POST /api/replay/{record_id}        # 复现单条攻击
GET  /api/replay/records            # 查看复现记录
```

---

## 7. 项目结构

```
Gov-Com-safeagent/
├── ai_service/                      # 后端 (Python/FastAPI)
│   ├── main.py                      # API 入口 & 路由
│   ├── config.py                    # 配置管理
│   ├── storage.py                   # SQLite 持久化
│   ├── security/                    # 安全检测引擎
│   │   ├── input_detector.py        # 输入检测编排
│   │   ├── rule_engine.py           # 规则引擎
│   │   ├── ai_detector.py           # AI 语义检测
│   │   ├── vector_poisoning_detector.py  # 向量投毒检测
│   │   ├── unicode_decoder.py       # Unicode 高级解码
│   │   ├── llm_classifier.py        # LLM 语义分类仲裁
│   │   ├── adversarial_mutator.py   # 对抗样本变异 (10策略)
│   │   ├── approval_engine.py       # 审批引擎
│   │   └── ...
│   ├── tools/                       # 工具执行
│   │   └── docker_executor.py       # Docker 沙箱执行器
│   ├── websocket/                   # WebSocket 实时通信
│   │   └── manager.py               # 连接管理 & 事件推送
│   ├── audit/                       # 审计 & 评测
│   │   ├── attack_samples.json      # 210条评测样本
│   │   ├── run_evaluation.py        # 评测运行脚本
│   │   ├── generate_report.py       # 报告生成脚本
│   │   ├── evaluation_report.json   # 评测结果
│   │   └── attack_replay.py         # 攻击复现
│   ├── plugins/                     # 插件安全
│   ├── gov_agent_graph/             # 政企 Agent 图
│   ├── models/                      # Pydantic 数据模型
│   └── .env.example                 # 环境变量模板
│
├── frontend/                        # 前端 (Vue 3)
│   ├── src/
│   │   ├── pages/
│   │   │   ├── HomePage.vue         # 主页 (4 个功能Tab)
│   │   │   └── EvaluationPage.vue   # 评测报告页
│   │   ├── components/
│   │   │   ├── chat/ChatPanel.vue   # 智能问答
│   │   │   ├── security/SecurityPanel.vue  # 安全检测 (含6子Tab)
│   │   │   ├── tools/ToolPanel.vue  # 工具管控
│   │   │   └── audit/AuditPanel.vue # 审计追溯
│   │   ├── composables/
│   │   │   └── useWebSocket.ts      # WebSocket Composable
│   │   └── router/
│   └── package.json
│
├── docker/
│   └── tool-sandbox/                # 工具执行沙箱
│       ├── Dockerfile               # Alpine 最小化镜像
│       └── entrypoint.sh            # 工具路由脚本
│
├── deploy/
│   ├── docker-compose.yml           # Docker Compose 编排
│   ├── Dockerfile                   # AI 服务镜像
│   ├── nginx.conf                   # Nginx 配置
│   ├── start.sh                     # Linux/Mac 启动脚本
│   └── start_production.bat         # Windows 启动脚本
│
└── 技术方案报告.md                   # 技术方案文档
```

---

## 8. 常见问题

### Q: 启动后 LLM 语义分类不工作？

检查 `ai_service/.env` 中是否填写了 `ZHIPU_API_KEY`。未配置时系统会自动降级为本地启发式规则。

### Q: 工具沙箱提示 Docker 不可用？

系统设计了自动降级机制 — Docker 不可用时工具执行自动切换为本地模拟模式，不影响核心检测功能。

### Q: 前端页面空白？

1. 确认已执行 `npm run build`
2. 检查 Nginx 配置中 `root` 路径是否正确
3. 查看浏览器控制台是否有网络请求错误

### Q: WebSocket 连接失败？

1. 检查 Nginx 是否包含 `/ws/` 的代理配置
2. 浏览器控制台查看 WebSocket 连接状态
3. 系统会自动回退到 WebSocket 不可用时的备用策略（按需 HTTP 请求）

### Q: 如何增加自定义检测规则？

编辑 `ai_service/security/rule_engine.py` 中的 `attack_patterns` 字典，添加新的正则模式即可。正则模式权重 0.4~0.5。

### Q: 评测报告如何获取 PDF？

```bash
python generate_report.py --pdf
# 用浏览器打开 evaluation_report.html
# Ctrl+P → 另存为 PDF
```
