# ============================================================
# SafeAgent 工具执行沙箱
# 最小化 Alpine 镜像，仅包含工具执行必需的依赖
# ============================================================
FROM alpine:3.20

LABEL description="SafeAgent Tool Sandbox - Isolated tool execution environment"
LABEL version="1.0"

# 创建非 root 用户
RUN addgroup -g 1000 sandbox && \
    adduser -D -u 1000 -G sandbox -h /home/sandbox -s /bin/sh sandbox

# 安装最小依赖
RUN apk add --no-cache \
    python3 \
    py3-pip \
    curl \
    jq \
    bash

# 安装 Python 依赖
RUN pip3 install --no-cache-dir \
    requests==2.31.0 \
    --break-system-packages

# 创建工具脚本目录
RUN mkdir -p /tools /data && \
    chown -R sandbox:sandbox /tools /data

# 复制工具执行入口脚本
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown sandbox:sandbox /entrypoint.sh

# 创建工作目录
WORKDIR /tools

# 切换到非 root 用户
USER sandbox

# 只读根文件系统在 docker run 时通过 --read-only 设置
ENTRYPOINT ["/entrypoint.sh"]
