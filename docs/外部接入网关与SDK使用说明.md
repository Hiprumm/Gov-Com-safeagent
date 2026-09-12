# 外部接入网关与 SDK 使用说明

> **产品线定位**：本仓库以 **ai_service（Python/FastAPI）为唯一主后端**。`gateway/`（Agent 前置安全网关）与 `gov-safeagent-sdk/`（Python SDK）是面向**「外部 Agent 接入」场景的独立产品线**，部署形态、端口与主系统不同，**不属于主链路组件**。需要部署主系统时请以 [README.md](../README.md) 与 [部署与安全加固指南.md](../部署与安全加固指南.md) 为准。

---

## 1. 适用场景

客户已有自己的 Agent（LangChain / LlamaIndex / Dify / 自研 Agent），希望在不替换内核的前提下获得本系统的安全能力：

| 形态 | 说明 | 改造量 |
|------|------|--------|
| 形态 1（SDK 嵌入） | `SecurityGuard` 嵌入任意 Agent 进程内，全链路守卫 | <10 行 |
| 形态 2（Middleware） | gateway 反向代理前置，Agent **不改一行代码** | 0 |
| 形态 3（Sidecar） | gateway 与 Agent 同机部署（容器场景），用法同形态 2 | 0 |

---

## 2. 目录结构

```
gov-safeagent-sdk/              # Python SDK（pip 包）
├── gov_safeagent_sdk/
│   ├── guard.py                # SecurityGuard：输入检测/工具守卫/计划评估/输出脱敏
│   ├── client.py               # SafeAgentClient：远程调用 gateway /api/sdk/*
│   └── adapters/               # LangChain / LlamaIndex / Dify 适配器
├── examples/                   # 接入示例
└── pyproject.toml              # pip install -e . 或 ".[gateway]"

gateway/                        # Agent 前置安全网关（FastAPI）
├── main.py                     # 反向代理 + 三个拦截点 + /api/sdk/* 远程 API
└── interceptors.py             # 请求前检测 / 工具调用代理 / 响应后过滤
```

---

## 3. SDK 形态（进程内嵌入）

### 3.1 安装

```bash
cd gov-safeagent-sdk
pip install -e .                # SDK 形态
pip install -e ".[gateway]"     # 需要网关形态时
```

安全核心定位（三种方式任选其一）：
1. 环境变量 `GOV_SAFEAGENT_CORE=<本仓库>/ai_service`
2. 在仓库目录内运行（自动向上查找）
3. `SecurityGuard(core_path=".../ai_service")`

### 3.2 核心接口

```python
from gov_safeagent_sdk import SecurityGuard

guard = SecurityGuard()
v = guard.detect_sync("帮我查询公积金政策")          # 输入检测（11 层管线）
t = guard.check_tool("sess-1", "write_file", {...})  # 能力令牌+参数守卫（默认 deny）
guard.grant_tool("sess-1", "write_file")             # 审批解锁（限定范围，TTL 1h）
p = guard.assess_plan([{ "name": "execute_command", "args": {...} }])  # 序列风险+不可逆熔断
out = guard.filter_output(llm_answer)                # PII/密钥脱敏
await guard.detect_async(text)                       # 异步接口
```

### 3.3 框架适配器

```python
from gov_safeagent_sdk import SecurityGuard
from gov_safeagent_sdk.adapters import GuardedTool, GuardedQueryEngine, DifyGuardTool

guard = SecurityGuard()
safe_search = GuardedTool(my_langchain_tool, guard, session_id="s1")     # LangChain
engine = GuardedQueryEngine(index.as_query_engine(), guard)              # LlamaIndex
schema = DifyGuardTool(guard).build_openapi_schema()                     # Dify 自定义工具
```

---

## 4. 网关形态（Agent 零改造）

### 4.1 启动

```bash
# 原拓扑: 客户端 ──▶ http://agent:8080
# 新拓扑: 客户端 ──▶ http://gateway:8081 ──▶ http://agent:8080

cd Gov-Com-safeagent
UPSTREAM_URL=http://127.0.0.1:8080 python -X utf8 gateway/main.py   # 默认 8081
```

环境变量：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `UPSTREAM_URL` | `http://127.0.0.1:8080` | 上游 Agent 地址 |
| `GATEWAY_PORT` | `8081` | 网关监听端口（**注意与主后端 8080 区分**） |
| `UPSTREAM_TOOL_PATH` | 空 | 配置后工具调用校验通过会继续代理到上游真实工具执行端点 |

### 4.2 三个拦截点

| 拦截点 | 机制 | 效果 |
|--------|------|------|
| ① 请求前检测 | 11 层输入检测（high/critical） | 注入攻击 403，不达上游 |
| ② 工具调用代理 | `POST /api/gateway/tool-call` | 能力令牌默认 deny + 审批解锁 |
| ③ 响应后过滤 | PII/密钥递归脱敏 | 手机号/密钥出网前打码 |

### 4.3 管理 / 远程 API

| 端点 | 用途 |
|------|------|
| `GET /api/gateway/health` | 健康检查（含上游地址与拦截器统计） |
| `GET /api/gateway/stats` | 拦截器命中统计 |
| `POST /api/gateway/tool-call` | 工具调用代理（Agent 侧接入方式见 SDK README） |
| `POST /api/gateway/grant-tool` | 审批解锁（对应人工审批动作） |
| `POST /api/sdk/detect` | SDK 远程输入检测（`SafeAgentClient` 服务端） |
| `POST /api/sdk/tool-check` | SDK 远程工具校验 |
| `POST /api/sdk/output-filter` | SDK 远程输出过滤 |

---

## 5. 与主系统的差异（勿混淆）

| 维度 | 主系统（ai_service） | gateway | gov-safeagent-sdk |
|------|---------------------|---------|-------------------|
| 端口 | 8080 | 8081 | 无（进程内） |
| 部署形态 | FastAPI 单体 + 前端 | 反向代理中间件 | pip 包 |
| 业务范围 | 检测/审批/审计/治理/用户/合规 | 仅外部 Agent 接入防护 | 仅嵌入防护能力 |
| 鉴权 | `X-Auth-Token` + 权限点；`AUTH_ENABLED` 时 `X-API-Key` | 透传上游 | 进程内无鉴权 |
| 启动入口 | `ai_service/main.py` | `gateway/main.py` | import |

> 网关形态对"Agent 进程内工具执行"无感知——工具级控制需 Agent 把工具调用指向 `/api/gateway/tool-call`（②），或直接用 SDK 形态（进程内全覆盖）。
> 能力令牌按进程隔离：网关侧 grant 与 Agent 进程内 SDK 是两个令牌池，勿混用。

---

## 6. 验证

```bash
# 前置：后端 Agent 运行在 8080（模拟客户现有 Agent）
# 在仓库根目录执行
python tests/test_sdk_gateway.py   # 31 项：SDK 单元 + 网关三拦截点端到端
```

---

## 7. 参考

- SDK 详细接入：`gov-safeagent-sdk/README.md`
- 网关实现：`gateway/main.py`、`gateway/interceptors.py`
