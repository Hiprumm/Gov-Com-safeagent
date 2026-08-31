# gov-safeagent-sdk

政企大模型智能体安全防护 SDK —— 把安全能力从 Agent 内核剥离，**客户不需要换掉现有 Agent**。

三种交付形态：

```
形态 1（SDK）       : SecurityGuard 嵌入任意 Agent 进程内
形态 2（Middleware）: gateway 反向代理前置，Agent 不改一行代码
形态 3（Sidecar）   : gateway 与 Agent 同机部署（容器场景），用法同形态 2
```

## 安装

```bash
cd gov-safeagent-sdk
pip install -e .                    # SDK 形态
pip install -e ".[gateway]"         # 需要网关形态时
# 安全核心定位（三种方式任选其一）：
#   1. 环境变量 GOV_SAFEAGENT_CORE=<本仓库>/ai_service
#   2. 在仓库目录内运行（自动向上查找）
#   3. SecurityGuard(core_path=".../ai_service")
```

## 形态 1：SDK 嵌入（<10 行）

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

## 形态 2：Gateway 中间件（Agent 零改造）

```bash
# 原拓扑: 客户端 ──▶ http://agent:8080
# 新拓扑: 客户端 ──▶ http://gateway:8081 ──▶ http://agent:8080
cd Gov-Com-safeagent
UPSTREAM_URL=http://127.0.0.1:8080 python -X utf8 gateway/main.py   # 默认 8081
```

三个拦截点（均可阻断/改写）：

| 拦截点 | 机制 | 效果 |
|--------|------|------|
| ① 请求前检测 | 11 层输入检测（high/critical） | 注入攻击 403，不达上游 |
| ② 工具调用代理 | `POST /api/gateway/tool-call` | 能力令牌默认 deny + 审批解锁 |
| ③ 响应后过滤 | PII/密钥递归脱敏 | 手机号/密钥出网前打码 |

远程客户端：`SafeAgentClient("http://127.0.0.1:8081")`，`detect_sync/detect_async/check_tool/filter_output`。

## 框架适配器

```python
from gov_safeagent_sdk import SecurityGuard
from gov_safeagent_sdk.adapters import GuardedTool, GuardedQueryEngine, DifyGuardTool

guard = SecurityGuard()
safe_search = GuardedTool(my_langchain_tool, guard, session_id="s1")     # LangChain
engine = GuardedQueryEngine(index.as_query_engine(), guard)              # LlamaIndex
schema = DifyGuardTool(guard).build_openapi_schema()                     # Dify 自定义工具
```

## 验证

```bash
# 前置：后端 Agent 运行在 8080（模拟客户现有 Agent）
python -X utf8 test_sdk_gateway.py     # 31 项：SDK 单元 + 网关三拦截点端到端
```

## 边界说明

- 网关形态对"Agent 进程内工具执行"无感知——工具级控制需 Agent 把工具调用指向
  `/api/gateway/tool-call`（②），或直接用 SDK 形态（进程内全覆盖）
- 能力令牌按进程隔离：网关侧 grant 与 Agent 进程内 SDK 是两个令牌池，勿混用
