# ============================================================
# 统一鉴权网关 gateway-lite 镜像（阶段8：一键部署补全）
# 构建: docker build -t safeagent-gateway -f deploy/gateway-lite.Dockerfile .
#
# 说明：网关复用 ai_service 的共享模块（config/storage/auth/
# governance/permission），故镜像同时 COPY 两目录；
# main.py 按 ../ai_service 相对路径注入 sys.path，目录结构不可变更。
# ============================================================

FROM python:3.12-slim

WORKDIR /app

# Python 依赖（与 AI 服务同源，保证共享模块行为一致）
COPY ai_service/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# 共享模块 + 网关代码
COPY ai_service/ ./ai_service/
COPY gateway-lite/ ./gateway-lite/

WORKDIR /app/gateway-lite

EXPOSE 8090

# 单进程即可（无状态代理；限流/封锁计数已落共享库，可横向扩副本）
CMD ["python", "main.py"]
