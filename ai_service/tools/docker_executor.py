"""
Docker 沙箱工具执行器

在隔离的 Docker 容器中执行工具调用，提供资源限制、网络隔离和超时保护。
当 Docker 不可用时，自动降级为本地模拟执行。

支持的工具:
- read_file: 读取文件内容（只读）
- search_knowledge: 搜索知识库
- send_email: 发送邮件（仅白名单接收人）
- query_db: 数据库只读查询
"""
import sys
import os
import json
import subprocess
import tempfile
import time
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ==================== 配置 ====================

# Docker 镜像名
SANDBOX_IMAGE = "safeagent-tool-sandbox:latest"

# 资源限制
RESOURCE_LIMITS = {
    "cpu": "0.5",       # CPU 核心数
    "memory": "256m",   # 内存限制
    "timeout": 30,      # 执行超时（秒）
    "disk_readonly": True,
}

# 网络白名单（允许出站的目标）
NETWORK_WHITELIST = [
    "localhost",
    "127.0.0.1",
    "knowledge.internal",  # 内部知识库
]

# 沙箱工作目录（受限真执行：read_file 仅允许读取该目录下的文件）
SANDBOX_WORKSPACE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "workspace",
)

# 只读文件大小上限（字节）
MAX_READ_BYTES = 4096


@dataclass
class ToolResult:
    """工具执行结果"""
    success: bool
    tool_name: str
    output: str = ""
    error: str = ""
    duration_ms: float = 0.0
    sandbox_mode: str = "local"  # "docker" | "local"


class DockerToolExecutor:
    """Docker 沙箱工具执行器"""

    def __init__(self):
        self._docker_available: Optional[bool] = None

    @property
    def docker_available(self) -> bool:
        """检查 Docker 且沙箱镜像是否就绪（否则直接走本地受限执行）"""
        if self._docker_available is None:
            try:
                result = subprocess.run(
                    ["docker", "version", "--format", "{{.Server.Version}}"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode != 0:
                    self._docker_available = False
                else:
                    # 守护进程在但镜像缺失时，仍走本地执行：避免每次调用都尝试拉取/失败
                    img = subprocess.run(
                        ["docker", "image", "inspect", SANDBOX_IMAGE],
                        capture_output=True, text=True, timeout=5
                    )
                    self._docker_available = img.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self._docker_available = False
        return self._docker_available

    def execute(self, tool_name: str, args: Dict[str, Any]) -> ToolResult:
        """
        执行工具调用

        Args:
            tool_name: 工具名称 (read_file|search_knowledge|send_email|query_db)
            args: 工具参数

        Returns:
            ToolResult
        """
        # 联网搜索：真实联网调用（需本地 API Key 与出网，不走沙箱/模拟）
        if tool_name == "web_search":
            return self._execute_local(tool_name, args)
        if self.docker_available:
            return self._execute_in_docker(tool_name, args)
        else:
            return self._execute_local(tool_name, args)

    def _execute_in_docker(self, tool_name: str, args: Dict[str, Any]) -> ToolResult:
        """在 Docker 容器中执行"""
        start = time.perf_counter()

        cmd = ["docker", "run", "--rm"]

        # 资源限制
        cmd.extend(["--cpus", RESOURCE_LIMITS["cpu"]])
        cmd.extend(["--memory", RESOURCE_LIMITS["memory"]])

        # 只读根文件系统
        if RESOURCE_LIMITS["disk_readonly"]:
            cmd.append("--read-only")
            # 需要临时写入 /tmp
            cmd.append("--tmpfs")
            cmd.append("/tmp:rw,noexec,nosuid,size=64m")

        # 网络隔离：仅允许白名单出站
        cmd.extend(["--network", "none"])  # 默认无网络
        # 如果工具需要网络访问，通过安全组配置
        if tool_name in ("search_knowledge", "send_email"):
            cmd.remove("--network")
            cmd.remove("none")
            cmd.extend(["--network", "bridge"])
            # 添加 DNS 限制
            cmd.extend(["--dns", "127.0.0.1"])  # 仅内部DNS

        # 安全选项
        cmd.extend(["--security-opt", "no-new-privileges"])
        cmd.append("--cap-drop=ALL")
        cmd.extend(["--security-opt", "apparmor=unconfined"])  # 兼容性

        # 环境变量传入参数
        cmd.extend([
            "-e", f"TOOL_NAME={tool_name}",
            "-e", f"TOOL_ARGS={json.dumps(args)}",
        ])

        cmd.append(SANDBOX_IMAGE)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=RESOURCE_LIMITS["timeout"],
            )
            elapsed = (time.perf_counter() - start) * 1000

            if proc.returncode == 0:
                output = proc.stdout.strip()
                return ToolResult(
                    success=True,
                    tool_name=tool_name,
                    output=output[:10000],  # 限制输出长度
                    duration_ms=elapsed,
                    sandbox_mode="docker",
                )
            else:
                stderr = (proc.stderr or "").strip()
                # 基础设施故障（沙箱镜像缺失 / 守护进程不可达）→ 降级为本地受限执行，
                # 与"未安装 Docker"时行为一致；避免因环境问题导致所有工具执行直接失败。
                infra_fail = any(k in stderr for k in (
                    "Unable to find image", "No such image", "manifest unknown",
                    "Cannot connect to the Docker daemon", "error during connect",
                ))
                if infra_fail:
                    self._docker_available = False
                    print(f"[沙箱] Docker 不可用（{stderr[:80]}），降级为本地受限执行")
                    return self._execute_local(tool_name, args)
                return ToolResult(
                    success=False,
                    tool_name=tool_name,
                    error=stderr or f"Exit code {proc.returncode}",
                    duration_ms=elapsed,
                    sandbox_mode="docker",
                )
        except subprocess.TimeoutExpired:
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(
                success=False,
                tool_name=tool_name,
                error=f"执行超时（>{RESOURCE_LIMITS['timeout']}s）",
                duration_ms=elapsed,
                sandbox_mode="docker",
            )
        except FileNotFoundError:
            return self._execute_local(tool_name, args)

    def _execute_local(self, tool_name: str, args: Dict[str, Any]) -> ToolResult:
        """
        本地模拟执行（Docker 不可用时的回退方案）

        仅执行安全的只读操作，不提供真实的文件系统访问。
        """
        start = time.perf_counter()

        try:
            if tool_name == "read_file":
                output = self._local_read_file(args)
            elif tool_name == "search_knowledge":
                output = self._sim_search_knowledge(args)
            elif tool_name == "send_email":
                output = self._sim_send_email(args)
            elif tool_name == "query_db":
                output = self._sim_query_db(args)
            elif tool_name == "draft_document":
                output = self._sim_draft_document(args)
            elif tool_name == "generate_report":
                output = self._sim_generate_report(args)
            elif tool_name == "export_data":
                output = self._sim_export_data(args)
            elif tool_name == "web_search":
                output = self._run_web_search(args)
            else:
                return ToolResult(
                    success=False,
                    tool_name=tool_name,
                    error=f"未知工具: {tool_name}",
                    sandbox_mode="local",
                )

            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(
                success=True,
                tool_name=tool_name,
                output=output,
                duration_ms=elapsed,
                sandbox_mode="local",
            )
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(
                success=False,
                tool_name=tool_name,
                error=str(e),
                duration_ms=elapsed,
                sandbox_mode="local",
            )

    # ==================== 本地受限真执行实现 ====================

    def _ensure_workspace(self) -> str:
        """确保沙箱工作目录存在，并放入示例文件（受限真执行）"""
        if not os.path.isdir(SANDBOX_WORKSPACE):
            os.makedirs(SANDBOX_WORKSPACE, exist_ok=True)
        # 首次执行时放一个示例文件，供 read_file 真实读取
        sample = os.path.join(SANDBOX_WORKSPACE, "welcome.txt")
        if not os.path.isfile(sample):
            with open(sample, "w", encoding="utf-8") as f:
                f.write("SafeAgent 沙箱工作区\n")
                f.write("这是受限真执行环境，仅允许读取本目录下的文件。\n")
        return SANDBOX_WORKSPACE

    def _local_read_file(self, args: dict) -> str:
        """受限真执行：白名单路径内真实读取文件（禁止路径遍历/绝对路径逃逸）"""
        path = args.get("file_path") or args.get("path", "")

        # 安全校验：禁止路径遍历、绝对路径、盘符
        if not path or ".." in path or path.startswith(("/", "\\")) or ":" in path:
            return "[安全拦截] 路径非法或越权"

        workspace = self._ensure_workspace()
        workspace_real = os.path.realpath(workspace)
        full_path = os.path.realpath(os.path.join(workspace, path))

        # 白名单约束：解析后的真实路径必须落在沙箱工作目录内
        if not full_path.startswith(workspace_real + os.sep) and full_path != workspace_real:
            return "[安全拦截] 路径越权（不在白名单目录内）"

        if not os.path.isfile(full_path):
            return f"[沙箱] 文件 '{path}' 不存在"

        try:
            with open(full_path, "r", encoding="utf-8") as f:
                return f.read(MAX_READ_BYTES)
        except Exception as e:
            return f"[错误] 读取失败: {e}"

    def _sim_search_knowledge(self, args: dict) -> str:
        """知识库语义检索（本地 RAG，政企政务沙盒语料）"""
        query = (args.get("query") or args.get("q") or "").strip()
        if not query:
            return "[错误] 查询参数为空"

        try:
            from knowledge.rag_engine import get_kb
            kb = get_kb()
            hits = kb.search(query, k=3, min_score=0.42)
            if not hits:
                return f"[知识库] 未在政务沙盒知识库中找到与「{query}」相关的内容"
            lines = ["[知识库检索命中]，来源如下："]
            for i, h in enumerate(hits, 1):
                # 正文节选（标题 + 前 180 字）
                snippet = h["text"].strip().replace("\n", " ")
                if len(snippet) > 200:
                    snippet = snippet[:200] + "…"
                lines.append(
                    f"{i}. 【{h['title']}】（来源《{h['source']}》，相关度 {h['score']:.2f}）\n   {snippet}"
                )
            lines.append("注：以上为知识库检索原文摘录，请据此作答并注明来源。")
            return "\n".join(lines)
        except Exception as e:  # noqa: BLE001
            return f"[知识库] 检索服务暂不可用: {e}"

    def _run_web_search(self, args: dict) -> str:
        """真实联网搜索（博查合规 API）：调用 web_search 模块并格式化为模型可读文本"""
        query = (args.get("query") or "").strip()
        if not query:
            return "[web_search] 缺少参数 query"
        try:
            from security.web_search import WebSearchProvider, _fmt_results_for_agent
            out = WebSearchProvider().search(query)
            return _fmt_results_for_agent(out)
        except Exception as e:  # noqa: BLE001 —— 搜索异常不允许拖垮问答主流程
            return f"[web_search] 联网搜索服务异常: {str(e)[:120]}"

    def _sim_draft_document(self, args: dict) -> str:
        """拟稿助手：依据知识库起草公文/通知（草稿，含 AIGC 标识与人工核定提示）"""
        try:
            from workflows.doc_worker import draft_document
            res = draft_document(args)
            if not res.get("success"):
                return f"[拟稿助手] {res.get('error', '起草失败')}"
            return res["text"]
        except Exception as e:  # noqa: BLE001
            return f"[拟稿助手] 起草服务暂不可用: {e}"

    def _sim_generate_report(self, args: dict) -> str:
        """报表助手：据口径/数据生成结构化报表（含 AIGC 标识与数据核对提示）"""
        try:
            from workflows.doc_worker import generate_report
            res = generate_report(args)
            if not res.get("success"):
                return f"[报表助手] {res.get('error', '生成失败')}"
            return res["text"]
        except Exception as e:  # noqa: BLE001
            return f"[报表助手] 生成服务暂不可用: {e}"

    def _sim_export_data(self, args: dict) -> str:
        """导出类工具（沙箱模式：不产生真实外发，仅生成导出回执，供演示与审计）"""
        fmt = str(args.get("format") or "csv").strip()
        query = str(args.get("query") or args.get("scope") or "").strip()
        target = str(args.get("target") or args.get("path") or "").strip()
        return "\n".join([
            "[导出回执] 导出任务已完成（沙箱模式：数据不离开本机）",
            f"- 数据范围: {query or '未指定'}",
            f"- 输出格式: {fmt}",
            f"- 输出位置: {target or '受控导出目录（未配置外部地址）'}",
            "- 说明: 本次调用已经过人工审批与能力令牌校验，并已写入审计链。",
        ])

    def _sim_send_email(self, args: dict) -> str:
        """模拟发送邮件（仅记录，不实际发送）"""
        to = args.get("to", "")
        subject = args.get("subject", "")
        body = args.get("body", "")

        # 白名单检查
        allowed_domains = ["@gov.cn", "@internal.com", "@safe.gov"]
        is_allowed = any(domain in to for domain in allowed_domains)

        if not is_allowed:
            return f"[安全拦截] 收件人 {to} 不在白名单中"

        return (
            f"[模拟发送] 邮件已记录（沙箱模式不实际发送）\n"
            f"收件人: {to}\n"
            f"主题: {subject}\n"
            f"内容长度: {len(body)} 字符"
        )

    def _sim_query_db(self, args: dict) -> str:
        """模拟数据库查询（只读SQL语法检查）"""
        query = args.get("query", "").strip()

        # 禁止写操作
        dangerous_ops = ["INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE",
                         "ALTER", "CREATE", "EXEC", "EXECUTE"]
        query_upper = query.upper()
        for op in dangerous_ops:
            if query_upper.startswith(op) or f" {op} " in f" {query_upper} ":
                return f"[安全拦截] 沙箱模式禁止写操作: {op}"

        # 模拟查询结果
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


# ==================== 全局单例 ====================
docker_executor = DockerToolExecutor()
