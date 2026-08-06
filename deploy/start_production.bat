@echo off
REM ============================================================
REM SafeAgent 一键启动 (Windows)
REM
REM 使用方法:
REM   1. 直接双击 start_production.bat
REM   2. 或在终端: start_production.bat [start|stop|clean|dev]
REM ============================================================
setlocal enabledelayedexpansion

set MODE=%1
if "%MODE%"=="" set MODE=start

REM 项目目录
set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..
set AI_DIR=%PROJECT_DIR%\ai_service
set FRONTEND_DIR=%PROJECT_DIR%\frontend
set DEPLOY_DIR=%SCRIPT_DIR%

cd /d "%SCRIPT_DIR%"

REM ======== 命令处理 ========
if /i "%MODE%"=="stop" (
    echo [STEP] 停止 Docker 服务...
    docker compose down
    echo [INFO] 所有服务已停止
    exit /b 0
)
if /i "%MODE%"=="clean" (
    echo [STEP] 清理容器和镜像...
    docker compose down -v --rmi all 2>nul
    echo [INFO] 清理完成
    exit /b 0
)
if /i "%MODE%"=="dev" (
    echo [STEP] 开发模式启动...
    cd /d "%AI_DIR%"
    if not exist ".env" (
        echo [WARN] .env 不存在,从 .env.example 复制...
        copy .env.example .env 2>nul
    )
    pip install -r requirements.txt -q 2>nul
    echo [INFO] 启动开发服务器: http://localhost:8080
    python -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload --log-level info
    goto :end
)

echo.
echo  ================================================
echo   政企大模型智能体安全系统 - SafeAgent v4.0
echo  ================================================
echo.

REM ======== 1. 检查 Docker ========
echo [STEP] 检查 Docker...
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 未安装 Docker Desktop,请先安装
    echo   https://docs.docker.com/desktop/install/windows-install/
    pause
    exit /b 1
)
echo [INFO] Docker 就绪

REM ======== 2. 检查 .env ========
echo [STEP] 检查 .env 配置...
if not exist "%AI_DIR%\.env" (
    echo [WARN] .env 不存在
    if exist "%AI_DIR%\.env.example" (
        copy "%AI_DIR%\.env.example" "%AI_DIR%\.env" >nul
        echo [INFO] 已从 .env.example 创建 .env ^(请编辑填写智谱API Key^)
    ) else (
        echo [ERROR] .env.example 不存在
        pause
        exit /b 1
    )
)

REM ======== 3. 构建前端 ========
echo [STEP] 构建前端...
cd /d "%FRONTEND_DIR%"
if not exist "node_modules" (
    echo [INFO] 安装前端依赖...
    call npm install
)
call npm run build
if %errorlevel% neq 0 (
    echo [ERROR] 前端构建失败
    pause
    exit /b 1
)
echo [INFO] 前端构建完成

REM ======== 4. Docker Compose 启动 ========
echo [STEP] 启动 Docker 服务...
cd /d "%DEPLOY_DIR%"
docker compose up -d --build

REM ======== 5. 等待启动 ========
echo [INFO] 等待服务就绪...
timeout /t 5 /nobreak >nul

powershell -Command "try { $r=Invoke-WebRequest http://localhost:8080/api/health -UseBasicParsing; Write-Host '[INFO] AI服务就绪' } catch { Write-Host '[WARN] AI服务尚未就绪，请稍候...' }"

REM ======== 完成 ========
echo.
echo  ================================================
echo   部署完成!
echo  ================================================
echo   网页前端:  http://localhost
echo   API 文档:  http://localhost:8080/docs
echo   Health:    http://localhost:8080/api/health
echo  ------------------------------------------------
echo   停止服务:  start_production.bat stop
echo   查看日志:  docker compose -f deploy/docker-compose.yml logs -f
echo  ================================================
echo.

:end
pause
