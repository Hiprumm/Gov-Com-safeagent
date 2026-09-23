@echo off
REM ============================================================
REM SafeAgent 一键生产启动 (Windows) —— 阶段8 生产级改造
REM
REM 使用方法:
REM   start_production.bat            生产模式（默认）：装配密钥→构建→全栈启动→健康等待
REM   start_production.bat prod       同上
REM   start_production.bat dev        开发模式（仅 AI 后端本地直跑，不建容器）
REM   start_production.bat stop       停止所有服务
REM   start_production.bat clean      清理容器/卷/镜像（⚠ 数据将丢失）
REM   start_production.bat status     查看服务状态
REM
REM 密钥说明（与 start.sh --prod 同一套装配逻辑）:
REM   - deploy/.env            compose 插值用（ENV/PG/密钥注入）
REM   - deploy/secrets/        持久化密钥文件；已存在不轮换（幂等）
REM   - jwt_secret.key         Python(env) 与 Java(文件挂载) 同源，令牌互认
REM ============================================================
setlocal enabledelayedexpansion
chcp 65001 >nul

set MODE=%1
if "%MODE%"=="" set MODE=prod

set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..
set AI_DIR=%PROJECT_DIR%\ai_service
set FRONTEND_DIR=%PROJECT_DIR%\frontend
set DEPLOY_DIR=%SCRIPT_DIR%
set ENV_FILE=%DEPLOY_DIR%.env
set SECRETS_DIR=%DEPLOY_DIR%secrets
set COMPOSE_FILE=%DEPLOY_DIR%docker-compose.yml

cd /d "%DEPLOY_DIR%"

REM ======== 命令处理 ========
if /i "%MODE%"=="stop"   goto do_stop
if /i "%MODE%"=="clean"  goto do_clean
if /i "%MODE%"=="status" goto do_status
if /i "%MODE%"=="dev"    goto do_dev
if /i "%MODE%"=="prod"   goto do_prod
if /i "%MODE%"=="start"  goto do_prod
echo 用法: start_production.bat [prod^|dev^|stop^|clean^|status]
exit /b 1

:do_stop
echo [STEP] 停止所有 Docker 服务...
docker compose -f "%COMPOSE_FILE%" down
echo [INFO] 所有服务已停止
goto :end

:do_clean
echo [STEP] 清理所有容器、卷与镜像（⚠ 数据将丢失）...
docker compose -f "%COMPOSE_FILE%" down -v --rmi all 2>nul
echo [INFO] 清理完成
goto :end

:do_status
docker compose -f "%COMPOSE_FILE%" ps
goto :end

:do_dev
echo [STEP] 开发模式启动（仅 AI 后端本地直跑）...
cd /d "%AI_DIR%"
if not exist ".env" (
    if exist ".env.example" (
        copy .env.example .env >nul
        echo [INFO] 已从 .env.example 创建 .env，请编辑填写智谱API Key
    )
)
pip install -r requirements.txt -q 2>nul
echo [INFO] 启动开发服务器: http://localhost:8080
python -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload --log-level info
goto :end

REM ============================================================
REM 生产模式主流程
REM ============================================================
:do_prod
echo.
echo  ================================================
echo   政企大模型智能体安全系统 - SafeAgent v4.0
echo   生产一键部署
echo  ================================================
echo.

REM ======== 1. 检查 Docker ========
echo [STEP] 检查 Docker...
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] 未安装 Docker Desktop，请先安装:
    echo   https://docs.docker.com/desktop/install/windows-install/
    goto :fail
)
docker compose version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Compose 不可用，Docker 版本需不低于 20.10
    goto :fail
)
echo [INFO] Docker 就绪

REM ======== 2. 装配生产密钥（幂等） ========
call :generate_prod_env
if errorlevel 1 goto :fail

REM ======== 3. 构建产物（前端 + biz jar） ========
call :build_artifacts
if errorlevel 1 goto :fail

REM ======== 4. 全栈启动 ========
echo [STEP] 启动全栈服务（postgres-AI-biz-gateway-nginx-监控-备份）...
cd /d "%DEPLOY_DIR%"
docker compose -f "%COMPOSE_FILE%" --env-file "%ENV_FILE%" up -d --build
if errorlevel 1 (
    echo [ERROR] 服务启动失败，排查命令:
    echo   docker compose -f "%COMPOSE_FILE%" logs --tail=50
    goto :fail
)

REM ======== 5. 健康等待（网关确认 ai/biz 均 up） ========
call :wait_healthy

REM ======== 6. 汇总 ========
call :print_summary
goto :end

REM ============================================================
REM 子程序：密钥生成 / env 装配 / 构建 / 健康等待 / 汇总
REM ============================================================

REM ---- 生成 %1 字节随机 hex（PowerShell CSPRNG），输出变量 GEN_HEX ----
:gen_hex
setlocal
set BYTES=%~1
if "%BYTES%"=="" set BYTES=32
set HEX=
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "$b=New-Object byte[] %BYTES%;[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b);($b|ForEach-Object{$_.ToString('x2')})-join''"`) do set HEX=%%i
if "%HEX%"=="" (
    endlocal
    exit /b 1
)
endlocal & set GEN_HEX=%HEX%
exit /b 0

REM ---- 密钥文件幂等创建：存在且非空则不轮换 ----
:ensure_secret
if exist "%~1" (
    for %%F in ("%~1") do if %%~zF GTR 0 exit /b 0
)
call :gen_hex 32
if errorlevel 1 exit /b 1
> "%~1" echo %GEN_HEX%
exit /b 0

REM ---- 读文件首行到 READ_VAL ----
:read_first_line
set READ_VAL=
if exist "%~1" set /p READ_VAL=< "%~1"
exit /b 0

REM ---- .env 幂等补缺：已存在的变量不覆盖 ----
:ensure_env_var
findstr /B /C:"%~1=" "%ENV_FILE%" >nul 2>&1
if errorlevel 1 >> "%ENV_FILE%" echo %~1=%~2
exit /b 0

REM ---- 生产密钥装配：deploy/.env + deploy/secrets/ ----
:generate_prod_env
echo [STEP] 装配生产密钥（%ENV_FILE%）...
if not exist "%SECRETS_DIR%" mkdir "%SECRETS_DIR%"

call :ensure_secret "%SECRETS_DIR%\jwt_secret.key"
if errorlevel 1 ( echo [ERROR] 密钥生成失败 & exit /b 1 )
call :read_first_line "%SECRETS_DIR%\jwt_secret.key"
set JWT_SECRET=!READ_VAL!

call :ensure_secret "%SECRETS_DIR%\pg_password.key"
call :read_first_line "%SECRETS_DIR%\pg_password.key"
set PG_PASSWORD=!READ_VAL!

call :ensure_secret "%SECRETS_DIR%\mfa_secret.key"
call :read_first_line "%SECRETS_DIR%\mfa_secret.key"
set MFA_SECRET=!READ_VAL!

call :ensure_secret "%SECRETS_DIR%\graded_hmac.key"
call :read_first_line "%SECRETS_DIR%\graded_hmac.key"
set HMAC_KEY=!READ_VAL!

call :ensure_secret "%SECRETS_DIR%\zkp_proving.key"
call :read_first_line "%SECRETS_DIR%\zkp_proving.key"
set ZKP_KEY=!READ_VAL!

call :ensure_secret "%SECRETS_DIR%\grafana_password.key"
call :read_first_line "%SECRETS_DIR%\grafana_password.key"
set GRAFANA_PWD=!READ_VAL!

if not exist "%ENV_FILE%" type nul > "%ENV_FILE%"
call :ensure_env_var ENV production
call :ensure_env_var STORAGE_BACKEND postgres
call :ensure_env_var POSTGRES_DB safeagent
call :ensure_env_var POSTGRES_USER safeagent
call :ensure_env_var POSTGRES_PASSWORD !PG_PASSWORD!
call :ensure_env_var AUTH_JWT_SECRET !JWT_SECRET!
call :ensure_env_var AUTH_MFA_SECRET_KEY !MFA_SECRET!
call :ensure_env_var GRADED_HMAC_KEY !HMAC_KEY!
call :ensure_env_var ZKP_PROVING_KEY !ZKP_KEY!
call :ensure_env_var AUDIT_RETENTION_DAYS 180
call :ensure_env_var GRAFANA_ADMIN_PASSWORD !GRAFANA_PWD!
echo [INFO] 密钥就绪（已存在的不轮换）
exit /b 0

REM ---- 构建前端 + 检查 biz jar ----
:build_artifacts
echo [STEP] 构建前端...
cd /d "%FRONTEND_DIR%"
if not exist "node_modules" (
    echo [INFO] 安装前端依赖...
    call npm install
    if errorlevel 1 ( echo [ERROR] npm install 失败 & exit /b 1 )
)
call npm run build
if errorlevel 1 ( echo [ERROR] 前端构建失败 & exit /b 1 )
echo [INFO] 前端构建完成

echo [STEP] 检查 biz-service jar...
if not exist "%PROJECT_DIR%\biz-service\target\biz-service-0.1.0.jar" (
    echo [INFO] jar 不存在，执行 Maven 打包（跳过测试）...
    cd /d "%PROJECT_DIR%\biz-service"
    if exist "mvnw.cmd" (
        call mvnw.cmd -q -DskipTests package
    ) else (
        where mvn >nul 2>&1
        if errorlevel 1 (
            echo [ERROR] biz jar 缺失且无 Maven，请先执行: cd biz-service 然后 mvnw.cmd -DskipTests package
            exit /b 1
        )
        call mvn -q -DskipTests package
    )
    if not exist "target\biz-service-0.1.0.jar" (
        echo [ERROR] Maven 打包失败
        exit /b 1
    )
)
echo [INFO] biz jar 就绪
cd /d "%DEPLOY_DIR%"
exit /b 0

REM ---- 健康等待：轮询网关 8090，直到 ai/biz 均 up（最多 300s） ----
:wait_healthy
echo [STEP] 等待服务就绪（最多 300s）...
set /a TRIES=0
:wait_loop
powershell -NoProfile -Command "try{$j=Invoke-RestMethod 'http://localhost:8090/api/gateway/health' -UseBasicParsing -TimeoutSec 5;if($j.ai_health -eq 'up' -and $j.biz_health -eq 'up'){exit 0}}catch{};exit 1" >nul 2>&1
if not errorlevel 1 (
    echo [INFO] 网关/AI/Biz 全链路就绪
    exit /b 0
)
set /a TRIES+=1
if !TRIES! GEQ 100 (
    echo [WARN] 300s 内未观察到全链路 up，排查命令:
    echo   docker compose -f "%COMPOSE_FILE%" logs --tail=50
    exit /b 1
)
timeout /t 3 /nobreak >nul
goto wait_loop

REM ---- 部署汇总 ----
:print_summary
echo.
echo  ================================================
echo   部署完成!
echo  ================================================
echo   网页前端:   http://localhost
echo   统一网关:   http://localhost:8090/api/gateway/health
echo  ------------------------------------------------
echo   初始口令（生产模式首启生成一次）:
echo     docker exec safeagent-biz cat /app/data/initial_credentials.txt
echo   特权账号首登强制 MFA 注册；口令文件分发后建议删除。
echo  ------------------------------------------------
echo   停止服务:   start_production.bat stop
echo   查看状态:   start_production.bat status
echo   查看日志:   docker compose -f "%COMPOSE_FILE%" logs -f
echo  ================================================
echo.
exit /b 0

:fail
echo [ERROR] 启动失败，请检查上方日志
goto :end

:end
endlocal
pause
