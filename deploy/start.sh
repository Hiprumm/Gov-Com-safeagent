#!/bin/bash
# ============================================================
# SafeAgent 一键启动脚本 (Linux / macOS) —— 阶段8 生产级改造
#
# 使用方法:
#   chmod +x start.sh
#   ./start.sh --prod      # 生产模式（推荐）：生成随机密钥→构建→全栈启动→健康等待
#   ./start.sh             # 同 --prod（默认即生产）
#   ./start.sh --dev       # 开发模式（仅 AI 后端本地直跑，不建容器）
#   ./start.sh --stop      # 停止所有服务
#   ./start.sh --clean     # 清理所有容器和卷（⚠ 含数据）
#   ./start.sh --status    # 查看服务状态
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEPLOY_DIR="$SCRIPT_DIR"
ENV_FILE="$DEPLOY_DIR/.env"
SECRETS_DIR="$DEPLOY_DIR/secrets"
COMPOSE="docker compose -f $DEPLOY_DIR/docker-compose.yml"

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

# 生成 32 字节 hex 密钥（仅当文件不存在——幂等，避免轮换导致 DB/令牌失效）
ensure_secret() {  # $1=输出文件
    if [ ! -s "$1" ]; then
        openssl rand -hex 32 > "$1"
        chmod 600 "$1"
    fi
}

# ============================================================
# 生产密钥装配：deploy/.env（容器插值）+ deploy/secrets/jwt_secret.key（biz 文件挂载）
# ============================================================
generate_prod_env() {
    log_step "装配生产密钥（$ENV_FILE）..."
    mkdir -p "$SECRETS_DIR"
    chmod 700 "$SECRETS_DIR" 2>/dev/null || true

    # JWT 密钥特殊：Python(env) 与 Java(文件) 必须同源 → 先落文件再回填 env
    ensure_secret "$SECRETS_DIR/jwt_secret.key"
    JWT_SECRET="$(cat "$SECRETS_DIR/jwt_secret.key")"

    # .env 已存在则只补缺失项（不轮换已生效密钥）
    ensure_env_var() {  # $1=var名 $2=值
        if ! grep -q "^$1=" "$ENV_FILE" 2>/dev/null; then
            echo "$1=$2" >> "$ENV_FILE"
        fi
    }
    touch "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    ensure_env_var "ENV" "production"
    ensure_env_var "STORAGE_BACKEND" "postgres"
    ensure_env_var "POSTGRES_DB" "safeagent"
    ensure_env_var "POSTGRES_USER" "safeagent"
    [ -s "$SECRETS_DIR/pg_password.key" ] || openssl rand -hex 16 > "$SECRETS_DIR/pg_password.key"
    chmod 600 "$SECRETS_DIR/pg_password.key" 2>/dev/null || true
    ensure_env_var "POSTGRES_PASSWORD" "$(cat "$SECRETS_DIR/pg_password.key")"
    ensure_env_var "AUTH_JWT_SECRET" "$JWT_SECRET"
    ensure_env_var "AUTH_MFA_SECRET_KEY" "$(ensure_secret "$SECRETS_DIR/mfa_secret.key"; cat "$SECRETS_DIR/mfa_secret.key")"
    ensure_env_var "GRADED_HMAC_KEY" "$(ensure_secret "$SECRETS_DIR/graded_hmac.key"; cat "$SECRETS_DIR/graded_hmac.key")"
    ensure_env_var "ZKP_PROVING_KEY" "$(ensure_secret "$SECRETS_DIR/zkp_proving.key"; cat "$SECRETS_DIR/zkp_proving.key")"
    ensure_env_var "AUDIT_RETENTION_DAYS" "180"
    # Grafana 管理口令（首次生成后不变）
    [ -s "$SECRETS_DIR/grafana_password.key" ] || openssl rand -hex 12 > "$SECRETS_DIR/grafana_password.key"
    chmod 600 "$SECRETS_DIR/grafana_password.key" 2>/dev/null || true
    ensure_env_var "GRAFANA_ADMIN_PASSWORD" "$(cat "$SECRETS_DIR/grafana_password.key")"
    log_info "密钥就绪（已存在的不轮换）✓"
}

# ============================================================
# 环境检测：docker / 内存 / cosign
# ============================================================
check_environment() {
    log_step "检查环境..."
    if ! command -v docker &> /dev/null; then
        log_error "未安装 Docker，请先安装: https://docs.docker.com/get-docker/"
        exit 1
    fi
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose 不可用，Docker 版本需 ≥20.10"
        exit 1
    fi
    log_info "Docker $(docker --version) ✓"

    # 内存 ≥4G 警告（全栈 9 服务实测最低 ~3.5G）
    MEM_GB="$(docker info --format '{{.MemTotal}}' 2>/dev/null | awk '{printf "%.1f", $1/1024/1024/1024}' || echo 0)"
    if command -v awk &> /dev/null && [ "$(echo "$MEM_GB < 4" | bc 2>/dev/null || echo 1)" = "1" ] 2>/dev/null; then
        [ "$(echo "$MEM_GB > 0" | bc 2>/dev/null || echo 0)" = "1" ] && \
            log_warn "可用内存 ${MEM_GB}G < 4G，全栈（PG+AI+网关+Biz+监控）可能 OOM，建议 ≥4G"
    fi

    # cosign 镜像验签（可选：离线内网可跳过）
    if command -v cosign &> /dev/null; then
        log_info "cosign 已安装：生产镜像可用 'cosign verify' 验签后再 up"
    else
        log_warn "cosign 未安装：跳过镜像验签（内网部署可接受；互联网部署建议安装 cosign）"
    fi
}

# ============================================================
# 构建：前端 + biz jar
# ============================================================
build_artifacts() {
    log_step "构建前端..."
    cd "$PROJECT_DIR/frontend"
    if [ ! -d "node_modules" ]; then
        log_info "安装前端依赖..."
        npm install --silent
    fi
    npm run build --silent
    log_info "前端构建完成 ✓"

    log_step "检查 biz-service jar..."
    if [ ! -f "$PROJECT_DIR/biz-service/target/biz-service-0.1.0.jar" ]; then
        log_info "jar 不存在，执行 Maven 打包（免 Docker 内构建）..."
        cd "$PROJECT_DIR/biz-service"
        if [ -x ./mvnw ]; then
            ./mvnw -q -DskipTests package
        elif command -v mvn &> /dev/null; then
            mvn -q -DskipTests package
        else
            log_error "biz jar 缺失且无 Maven，请先在构建机执行: cd biz-service && ./mvnw -DskipTests package"
            exit 1
        fi
    fi
    log_info "biz jar 就绪 ✓"
}

# ============================================================
# 健康等待：网关(8090) → 网关自检确认 ai/biz 均 up
# ============================================================
wait_healthy() {
    log_step "等待服务就绪..."
    local deadline=$((SECONDS + 300))
    while [ $SECONDS -lt $deadline ]; do
        GW_JSON="$(curl -s http://localhost:8090/api/gateway/health 2>/dev/null || true)"
        if echo "$GW_JSON" | grep -q '"ai_health": *"up"' && echo "$GW_JSON" | grep -q '"biz_health": *"up"'; then
            log_info "网关/AI/Biz 全链路就绪 ✓"
            return 0
        fi
        sleep 3
    done
    log_warn "300s 内未观察到全链路 up，查看日志: $COMPOSE logs --tail=50"
    return 1
}

print_summary() {
    local PROD="$1"
    echo ""
    echo "  ╔════════════════════════════════════════════════════╗"
    echo "  ║                部署完成！                           ║"
    echo "  ╠════════════════════════════════════════════════════╣"
    echo "  ║  网页前端:   http://localhost  (HTTPS: https://localhost) ║"
    echo "  ║  统一网关:   http://localhost:8090/api/gateway/health ║"
    echo "  ║  Prometheus: http://localhost:9090（未对外暴露端口时用 compose 访问） ║"
    if [ "$PROD" = "1" ]; then
        echo "  ╠════════════════════════════════════════════════════╣"
        echo "  ║  初始口令（仅首启生成一次）:                        ║"
        echo "  ║    docker exec safeagent-biz cat /app/data/initial_credentials.txt ║"
        echo "  ║  特权账号首登强制 MFA 注册；口令文件分发后建议删除。  ║"
    else
        echo "  ║  演示口令: admin/admin123（生产请用 --prod）        ║"
    fi
    echo "  ╠════════════════════════════════════════════════════╣"
    echo "  ║  停止服务:   $0 --stop                             ║"
    echo "  ║  查看状态:   $0 --status                           ║"
    echo "  ║  查看日志:   $COMPOSE logs -f                      ║"
    echo "  ╚════════════════════════════════════════════════════╝"
    echo ""
}

# ======== 命令处理 ========
MODE="${1:---prod}"
case "$MODE" in
    --stop)
        log_step "停止所有 Docker 服务..."
        $COMPOSE down
        log_info "所有服务已停止"
        exit 0
        ;;
    --clean)
        log_step "清理所有容器、卷与镜像（⚠ 数据将丢失）..."
        $COMPOSE down -v --rmi all 2>/dev/null || true
        log_info "清理完成"
        exit 0
        ;;
    --status)
        $COMPOSE ps
        exit 0
        ;;
    --dev)
        log_step "开发模式启动（仅 AI 后端，直接运行不构建容器）..."
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
    --prod|start|--start|"")
        ;;
    *)
        echo "用法: $0 [--prod|--dev|--stop|--clean|--status]"
        exit 1
        ;;
esac

print_banner
PROD=1

# ======== 1. 环境 + 密钥 + 构建 ========
check_environment
generate_prod_env
build_artifacts

# ======== 2. 全栈启动（.env 由 compose 从 deploy/ 工作目录自动读取） ========
log_step "启动全栈服务（postgres→ai→biz→gateway→nginx→监控→备份）..."
cd "$DEPLOY_DIR"
$COMPOSE up -d --build

# ======== 3. 健康等待 ========
wait_healthy || true

# ======== 4. 汇总 ========
print_summary "$PROD"
