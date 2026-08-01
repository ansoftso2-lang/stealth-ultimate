@echo off
chcp 65001 >nul
title Stealth Ultimate - Fully Automated Builder

set "GITHUB_TOKEN=%1"
if "%GITHUB_TOKEN%"=="" set "GITHUB_TOKEN=%STEALTH_GITHUB_TOKEN%"
if "%GITHUB_TOKEN%"=="" (
    echo [ERROR] GitHub token not provided.
    echo.
    echo Usage: build.bat YOUR_GITHUB_TOKEN
    echo Or set environment variable: STEALTH_GITHUB_TOKEN
    echo.
    pause
    exit /b 1
)

set "REPO_NAME=stealth-ultimate"

echo ========================================
echo   Stealth Ultimate - Automated Builder
echo ========================================
echo.

where git >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Git is not installed.
    pause
    exit /b 1
)

where gh >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] GitHub CLI (gh) is not installed.
    pause
    exit /b 1
)

echo [INFO] Logging in to GitHub...
echo %GITHUB_TOKEN% | gh auth login --with-token >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to authenticate with GitHub.
    pause
    exit /b 1
)

for /f "delims=" %%i in ('gh api user --jq .login 2^>nul') do set "GITHUB_USER=%%i"
if "%GITHUB_USER%"=="" (
    echo [ERROR] Failed to get GitHub username.
    pause
    exit /b 1
)

set "REPO=%GITHUB_USER%/%REPO_NAME%"
echo [INFO] User: %GITHUB_USER%
echo [INFO] Repository: %REPO%
echo.

echo [INFO] Creating/updating repository...
gh repo create %REPO% --public --source=. --remote=origin --push --confirm >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Repository exists or push failed, trying manual push...
    git init
    git remote set-url origin https://%GITHUB_TOKEN%@github.com/%REPO%.git >nul 2>&1
    if %ERRORLEVEL% NEQ 0 git remote add origin https://%GITHUB_TOKEN%@github.com/%REPO%.git
    git branch -M main
    git add .
    git commit -m "feat: Stealth Ultimate" >nul 2>&1
    git push -u origin main -f
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to push.
        pause
        exit /b 1
    )
)

echo [INFO] Code pushed successfully.
echo.
echo [INFO] Triggering build workflow...
gh workflow run build.yml --repo %REPO% --ref main
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to trigger workflow.
    pause
    exit /b 1
)

echo [INFO] Workflow triggered! Waiting for completion...
echo This takes ~5-10 minutes.
echo.

set "ATTEMPTS=0"
:wait_loop
set /a ATTEMPTS+=1
timeout /t 30 /nobreak >nul
gh run list --repo %REPO% --workflow=build.yml --limit 1 --json status,conclusion --jq '.[0]' > run_status.json 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Waiting... (attempt %ATTEMPTS%)
    goto wait_loop
)

for /f "delims=" %%i in (run_status.json) do set "STATUS=%%i"
echo [INFO] Status: %STATUS%

echo %STATUS% | findstr "completed" >nul
if %ERRORLEVEL% NEQ 0 goto wait_loop

echo %STATUS% | findstr "success" >nul
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Build failed!
    echo https://github.com/%REPO%/actions
    del run_status.json 2>nul
    pause
    exit /b 1
)

echo.
echo [INFO] Build completed! Downloading...
gh run download --repo %REPO% --name stealth-ultimate --dir . --clobber
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to download.
    pause
    exit /b 1
)

if exist "stealth_ultimate.zip" (
    echo.
    echo ========================================
    echo   BUILD SUCCESSFUL
    echo ========================================
    echo.
    echo Module: stealth_ultimate.zip
    echo Size:   for %%F in (stealth_ultimate.zip) do echo %%~zF bytes
    echo.
) else (
    echo [ERROR] Archive not found.
)

del run_status.json 2>nul
pause
exit /b 0
