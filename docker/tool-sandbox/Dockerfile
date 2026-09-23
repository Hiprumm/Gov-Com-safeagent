# ============================================================
# SafeAgent 工具执行沙箱镜像（safeagent-tool-sandbox:latest）
#
# 构建（deploy/docker-compose.yml 的 tool-sandbox 服务自动构建，或手动）:
#   docker build -t safeagent-tool-sandbox:latest docker/tool-sandbox
#
# 运行形态（与 docker_executor.py 的 docker run 参数、compose 服务配置对齐）:
# - 只读根文件系统（--read-only），/tmp 为 tmpfs 唯一可写路径 → 工作目录 /tmp
# - 非 root 用户（sandbox）运行，--cap-drop=ALL + no-new-privileges
# - 默认无网络（--network none），仅白名单工具由执行器按配置放开
# ============================================================
FROM python:3.12-slim

# 非 root 运行用户（系统账号，无登录 shell，最小权限）
RUN useradd -r -m -d /home/sandbox -s /usr/sbin/nologin sandbox

WORKDIR /app
COPY sandbox_runner.py /app/sandbox_runner.py
RUN chown sandbox:sandbox /app/sandbox_runner.py && chmod 0555 /app/sandbox_runner.py

# 只读根文件系统适配：工作目录落到 /tmp（宿主以 --read-only + tmpfs /tmp 运行）
WORKDIR /tmp
USER sandbox

# 入口：读环境变量 TOOL_NAME / TOOL_ARGS，结果写 stdout（退出码 0），
# 异常写 stderr 并以非 0 退出码结束
ENTRYPOINT ["python", "/app/sandbox_runner.py"]
