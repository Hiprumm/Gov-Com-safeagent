@echo off
rem ==========================================================
rem Biz-Service Maven Wrapper (Windows)
rem First run downloads Maven into ~/.m2/wrapper/dists.
rem Usage:  mvnw.cmd <goals>        e.g.  mvnw.cmd clean compile
rem ==========================================================
setlocal EnableExtensions EnableDelayedExpansion

set "APP_HOME=%~dp0"
set "WRAPPER_PROPS=%APP_HOME%.mvn\wrapper\maven-wrapper.properties"

if not exist "%WRAPPER_PROPS%" (
  echo [ERROR] Missing wrapper config: %WRAPPER_PROPS%
  exit /b 1
)

set "DIST_URL="
for /f "usebackq tokens=1,* delims==" %%A in ("%WRAPPER_PROPS%") do (
  if /i "%%A"=="distributionUrl" set "DIST_URL=%%B"
)
if not defined DIST_URL (
  echo [ERROR] 'distributionUrl' not found in wrapper config
  exit /b 1
)

for /f %%i in ('powershell -NoProfile -Command "$u='%DIST_URL%'; (Split-Path $u -Leaf) -replace '\.zip$',''"') do set "DIST_FOLDER=%%i"

set "DISTS_DIR=%USERPROFILE%\.m2\wrapper\dists"
set "DIST_HOME="
for /d %%d in ("%DISTS_DIR%\*") do if exist "%%~fd\bin\mvn.cmd" if not defined DIST_HOME set "DIST_HOME=%%~fd"

if not defined DIST_HOME (
  echo [WRAPPER] Downloading Maven: %DIST_FOLDER%
  if not exist "%DISTS_DIR%" mkdir "%DISTS_DIR%"
  set "ZIP=%TEMP%\%DIST_FOLDER%.zip"
  curl -fSL -o "!ZIP!" "%DIST_URL%"
  if errorlevel 1 (
    echo [ERROR] Failed to download: %DIST_URL%
    del "!ZIP!" >nul 2>nul
    exit /b 1
  )
  powershell -NoProfile -Command "Expand-Archive -Path '!ZIP!' -DestinationPath '%DISTS_DIR%' -Force"
  if errorlevel 1 (
    echo [ERROR] Failed to unzip Maven
    exit /b 1
  )
  del "!ZIP!" >nul 2>nul
  for /d %%d in ("%DISTS_DIR%\*") do if exist "%%~fd\bin\mvn.cmd" if not defined DIST_HOME set "DIST_HOME=%%~fd"
)

if not defined DIST_HOME (
  echo [ERROR] Could not locate mvn.cmd under %DISTS_DIR%
  exit /b 1
)

call "%DIST_HOME%\bin\mvn.cmd" %*
endlocal