"""
沙箱内工具执行器（safeagent-tool-sandbox 镜像入口）

由 ai_service/tools/docker_executor.py 通过环境变量注入调用：
- TOOL_NAME: 工具名称
- TOOL_ARGS: JSON 字符串形式的工具参数

行为约定（与 docker_executor._execute_in_docker 的解析逻辑对齐）：
- 成功：结果文本写 stdout，退出码 0
- 失败：错误信息写 stderr，退出码非 0（1=工具异常 2=参数/工具名非法 3=看门狗超时）

沙箱镜像为精简环境，不含宿主侧 knowledge/workflows 模块与 data/ 数据文件：
涉及真实数据源的工具（read_file/search_knowledge/draft_document）返回
"沙箱内无数据源"类结果；纯模拟类工具（send_email/query_db）与本地版行为对齐。
"""
import json
import os
import sys
import threading

# 单工具执行看门狗：超时强制退出（与外层 docker run 30s 超时对齐，双保险）
WATCHDOG_SECONDS = 30

# 只读文件大小上限（与本地版 docker_executor.MAX_READ_BYTES 对齐）
MAX_READ_BYTES = 4096

# 邮件接收人白名单域名（与本地版 _sim_send_email 对齐）
EMAIL_ALLOWED_DOMAINS = ["@gov.cn", "@internal.com", "@safe.gov"]

# 沙箱内工作目录（宿主以 --read-only + tmpfs /tmp 运行，/tmp 为唯一可写路径；
# 宿主未挂载数据卷时该目录为空，read_file 返回无数据源提示）
SANDBOX_WORKSPACE = "/tmp/workspace"


def _start_watchdog(seconds: int) -> threading.Timer:
    """
    启动内部看门狗：单工具执行超时强制退出进程。

    外层 subprocess 超时只杀掉 docker 客户端进程，容器可能继续运行；
    看门狗在容器内主动退出，确保容器随入口进程结束被 --rm 回收。
    """
    def _kill():
        print(f"[沙箱] 工具执行超过 {seconds}s，看门狗强制退出", file=sys.stderr)
        os._exit(3)  # Timer 线程内必须 os._exit（sys.exit 只结束当前线程）

    timer = threading.Timer(seconds, _kill)
    timer.daemon = True
    timer.start()
    return timer


# ==================== 工具实现（与本地版 _execute_local 行为对齐） ====================

def tool_read_file(args: dict) -> str:
    """
    受限真读取：安全校验与本地版 _local_read_file 完全一致。

    沙箱内无宿主 data/workspace 数据（默认不挂载），返回无数据源提示；
    若宿主通过卷挂载向 /tmp/workspace 注入了数据，则可真实读取（上限 4KB）。
    """
    path = args.get("file_path") or args.get("path", "")

    # 安全校验：禁止路径遍历、绝对路径、盘符（与本地版一致）
    if not path or ".." in path or path.startswith(("/", "\\")) or ":" in path:
        return "[安全拦截] 路径非法或越权"

    workspace = os.path.realpath(SANDBOX_WORKSPACE)
    full_path = os.path.realpath(os.path.join(workspace, path))

    # 白名单约束：解析后的真实路径必须落在沙箱工作目录内
    if not full_path.startswith(workspace + os.sep) and full_path != workspace:
        return "[安全拦截] 路径越权（不在白名单目录内）"

    if not os.path.isfile(full_path):
        return f"[沙箱] 文件 '{path}' 不存在（沙箱内无工作区数据源）"

    try:
        with open(full_path, "r", encoding="utf-8") as f:
            return f.read(MAX_READ_BYTES)
    except Exception as e:  # noqa: BLE001
        return f"[错误] 读取失败: {e}"


def tool_search_knowledge(args: dict) -> str:
    """知识库检索：沙箱内不含 RAG 引擎与政务语料，返回明确的无数据源提示。"""
    query = (args.get("query") or args.get("q") or "").strip()
    if not query:
        return "[错误] 查询参数为空"
    return (
        f"[知识库] 沙箱内无知识库数据源，无法检索「{query}」。"
        "如需真实检索，请在服务侧（本地受限执行或服务内 RAG）进行。"
    )


def tool_send_email(args: dict) -> str:
    """模拟发送邮件：与本地版 _sim_send_email 对齐（仅记录回执，不实际发送）。"""
    to = args.get("to", "")
    subject = args.get("subject", "")
    body = args.get("body", "")

    # 白名单检查（与本地版一致）
    if not any(domain in to for domain in EMAIL_ALLOWED_DOMAINS):
        return f"[安全拦截] 收件人 {to} 不在白名单中"

    return (
        f"[模拟发送] 邮件已记录（沙箱模式不实际发送）\n"
        f"收件人: {to}\n"
        f"主题: {subject}\n"
        f"内容长度: {len(body)} 字符"
    )


def tool_query_db(args: dict) -> str:
    """模拟数据库查询：与本地版 _sim_query_db 对齐（只读 SQL 检查 + 示例数据）。"""
    query = str(args.get("query", "")).strip()

    # 禁止写操作（与本地版一致）
    dangerous_ops = ["INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE",
                     "ALTER", "CREATE", "EXEC", "EXECUTE"]
    query_upper = query.upper()
    for op in dangerous_ops:
        if query_upper.startswith(op) or f" {op} " in f" {query_upper} ":
            return f"[安全拦截] 沙箱模式禁止写操作: {op}"

    # 模拟查询结果（与本地版一致）
    if "SELECT" in query_upper:
        if "users" in query.lower():
            return (
                "id | username | role\n"
                "1  | admin    | admin\n"
                "2  | user_001 | user\n"
                "3  | auditor  | auditor\n"
                "\n[沙箱] 示例数据（非真实数据库）"
            )
        return f"[沙箱] 模拟查询结果（查询: {query[:50]}...）"

    return "[错误] 仅支持 SELECT 查询"


def tool_draft_document(args: dict) -> str:
    """拟稿助手：沙箱内不含 workflows 拟稿服务依赖，返回无数据源提示。"""
    title = (args.get("title") or args.get("subject") or "").strip()
    lines = [
        "[拟稿助手] 沙箱内无拟稿服务依赖（workflows/knowledge 模块未随镜像分发），"
        "本次调用仅在沙箱内完成参数安全校验，未生成正式草稿。",
    ]
    if title:
        lines.append(f"- 拟稿主题: {title}")
    lines.append("如需真实拟稿，请在服务侧（本地受限执行或服务内 workflow）进行。")
    return "\n".join(lines)


# 工具注册表（沙箱镜像支持的 5 个工具）
TOOL_HANDLERS = {
    "read_file": tool_read_file,
    "search_knowledge": tool_search_knowledge,
    "send_email": tool_send_email,
    "query_db": tool_query_db,
    "draft_document": tool_draft_document,
}


def main() -> int:
    """入口：读取环境变量并分发执行，返回进程退出码。"""
    timer = _start_watchdog(WATCHDOG_SECONDS)

    tool_name = os.environ.get("TOOL_NAME", "")
    raw_args = os.environ.get("TOOL_ARGS", "{}")
    try:
        args = json.loads(raw_args) if raw_args.strip() else {}
        if not isinstance(args, dict):
            raise ValueError("TOOL_ARGS 必须是 JSON 对象")
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[沙箱] 参数解析失败: {e}", file=sys.stderr)
        return 2

    handler = TOOL_HANDLERS.get(tool_name)
    if handler is None:
        print(f"[沙箱] 沙箱镜像未实现该工具: {tool_name}", file=sys.stderr)
        return 2

    try:
        output = handler(args)
        print(output)
        return 0
    except Exception as e:  # noqa: BLE001 —— 异常统一转为非 0 退出码
        print(f"[沙箱] 工具执行异常: {e}", file=sys.stderr)
        return 1
    finally:
        timer.cancel()


if __name__ == "__main__":
    sys.exit(main())
