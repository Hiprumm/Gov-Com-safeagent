# ============================================================
# AI 服务 Docker 镜像
# 构建: docker build -t safeagent-ai -f deploy/Dockerfile .
# 运行: docker run -p 8080:8080 --env-file .env safeagent-ai
# ============================================================

FROM python:3.12-slim

WORKDIR /app

# 安装系统依赖(OCR 可选)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-chi-sim \
    && rm -rf /var/lib/apt/lists/*

# Python 依赖
COPY ai_service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 代码
COPY ai_service/ .

# 数据目录
RUN mkdir -p /app/data

EXPOSE 8080

# 生产启动: 多 worker, 无热重载
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2", "--log-level", "info"]
