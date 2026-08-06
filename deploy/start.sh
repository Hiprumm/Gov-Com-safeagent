#!/bin/bash
# ============================================================
# Docker 一键启动脚本 (Linux / macOS)
#
# 使用方法:
#   chmod +x start.sh
#   ./start.sh              # 生产模式启动
#   ./start.sh --dev        # 开发模式（仅后端，不构建容器）
#   ./start.sh --stop       # 停止所有服务
#   ./start.sh --clean      # 清理所有容器和镜像
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEPLOY_DIR="$SCRIPT_DIR"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC}  $1"; }

print_banner() {
    echo ""
    echo "  ╔══════════════════════════════════════════════╗"
    echo "  ║   政企大模型智能体安全系统 - SafeAgent v4.0    ║"
    echo "  ╚══════════════════════════════════════════════╝"
    echo ""
}

# ======== 命令处理 ========
MODE="${1:-start}"
case "$MODE" in
    --stop)
        log_step "停止所有 Docker 服务..."
        cd "$DEPLOY_DIR"
        docker compose down
        log_info "所有服务已停止"
        exit 0
        ;;
    --clean)
        log_step "清理所有容器和镜像..."
        cd "$DEPLOY_DIR"
        docker compose down -v --rmi all 2>/dev/null || true
        log_info "清理完成"
        exit 0
        ;;
    --dev)
        log_step "开发模式启动（仅后端，直接运行不构建容器）..."
        print_banner
        cd "$PROJECT_DIR/ai_service"
        if [ ! -f ".env" ]; then
            log_warn ".env 文件不存在，尝试从 .env.example 复制..."
            cp .env.example .env 2>/dev/null || log_error "请手动创建 .env 文件"
        fi
        pip install -r requirements.txt -q 2>/dev/null || true
        log_info "启动开发服务器: http://localhost:8080"
        python -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload --log-level info
        exit 0
        ;;
    start|--start|"")
        ;;
    *)
        echo "用法: $0 [--dev|--stop|--clean]"
        exit 1
        ;;
esac

print_banner

# ======== 步骤1: 检查 Docker ========
log_step "检查 Docker 环境..."
if ! command -v docker &> /dev/null; then
    log_error "未安装 Docker，请先安装: https://docs.docker.com/get-docker/"
    exit 1
fi
if ! docker compose version &> /dev/null; then
    log_error "Docker Compose 不可用，Docker版本需≥20.10"
    exit 1
fi
log_info "Docker $(docker --version) ✓"

# ======== 步骤2: 检查 .env ========
log_step "检查配置文件..."
if [ ! -f "$PROJECT_DIR/ai_service/.env" ]; then
    log_warn "未找到 ai_service/.env"
    if [ -f "$PROJECT_DIR/ai_service/.env.example" ]; then
        cp "$PROJECT_DIR/ai_service/.env.example" "$PROJECT_DIR/ai_service/.env"
        log_info "已从 .env.example 创建 .env（请编辑填写 API Key）"
    else
        log_error ".env.example 不存在"
        exit 1
    fi
fi

# ======== 步骤3: 构建前端 ========
log_step "构建前端..."
cd "$PROJECT_DIR/frontend"
if [ ! -d "node_modules" ]; then
    log_info "安装前端依赖..."
    npm install --silent
fi
npm run build --silent
log_info "前端构建完成 ✓"

# ======== 步骤4: Docker Compose 启动 ========
log_step "启动 Docker 服务..."
cd "$DEPLOY_DIR"
docker compose up -d --build

# ======== 步骤5: 等待启动 ========
log_info "等待服务就绪..."
sleep 3

# 健康检查
if command -v curl &> /dev/null; then
    for i in {1..10}; do
        if curl -s http://localhost:8080/api/health > /dev/null 2>&1; then
            log_info "AI 服务就绪 ✓"
            break
        fi
        sleep 2
    done
fi

# ======== 完成 ========
echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║            部署完成！                        ║"
echo "  ╠══════════════════════════════════════════════╣"
echo "  ║  网页前端:  http://localhost                 ║"
echo "  ║  API 文档:  http://localhost:8080/docs        ║"
echo "  ║  Health:    http://localhost:8080/api/health  ║"
echo "  ╠══════════════════════════════════════════════╣"
echo "  ║  停止服务:  $0 --stop                       ║"
echo "  ║  查看日志:  docker compose -f deploy/docker-compose.yml logs -f  ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""
