@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul
title Stealth Ultimate - GitHub Actions Builder

cd /d "%~dp0"

if not "%~1"=="" set "GH_TOKEN=%~1"
if not defined GH_TOKEN if defined STEALTH_GITHUB_TOKEN set "GH_TOKEN=%STEALTH_GITHUB_TOKEN%"

where git >nul 2>nul || (
  echo [ERROR] Git is not installed or is not in PATH.
  exit /b 1
)
where gh >nul 2>nul || (
  echo [ERROR] GitHub CLI is not installed or is not in PATH.
  exit /b 1
)
where powershell >nul 2>nul || (
  echo [ERROR] Windows PowerShell is not available.
  exit /b 1
)

if not defined GH_TOKEN (
  gh auth status >nul 2>nul || (
    echo [ERROR] GitHub authentication is required.
    echo Usage: build.bat YOUR_GITHUB_TOKEN
    echo Or set STEALTH_GITHUB_TOKEN once and run build.bat without arguments.
    exit /b 1
  )
)

for /f "delims=" %%R in ('gh repo view --json nameWithOwner --jq ".nameWithOwner" 2^>nul') do set "REPO=%%R"
if not defined REPO (
  echo [ERROR] Cannot determine the GitHub repository from the current git remote.
  exit /b 1
)

for /f "delims=" %%B in ('git branch --show-current') do set "BRANCH=%%B"
if not defined BRANCH set "BRANCH=main"

for /f "delims=" %%S in ('git status --porcelain') do set "DIRTY=1"
if defined DIRTY (
  echo [INFO] Committing current source and workflow changes...
  git add .github sources build.bat build.sh .gitignore
  git diff --cached --quiet
  if errorlevel 1 (
    git commit -m "chore: automated module build"
    if errorlevel 1 exit /b 1
  )
)

echo [INFO] Repository: %REPO%
echo [INFO] Branch: %BRANCH%
echo [INFO] Pushing source changes...
git push origin "%BRANCH%"
if errorlevel 1 (
  echo [ERROR] Git push failed.
  exit /b 1
)

echo [INFO] Triggering GitHub Actions workflow...
gh workflow run build.yml --repo "%REPO%" --ref "%BRANCH%"
if errorlevel 1 (
  echo [ERROR] Failed to trigger build.yml.
  exit /b 1
)

timeout /t 5 /nobreak >nul
set "RUN_ID="
for /f "delims=" %%I in ('gh run list --repo "%REPO%" --workflow build.yml --event workflow_dispatch --branch "%BRANCH%" --limit 1 --json databaseId --jq ".[0].databaseId"') do set "RUN_ID=%%I"
if not defined RUN_ID (
  echo [ERROR] Could not find the triggered workflow run.
  exit /b 1
)

echo [INFO] Waiting for workflow run %RUN_ID%...
gh run watch "%RUN_ID%" --repo "%REPO%" --exit-status
if errorlevel 1 (
  echo [ERROR] GitHub Actions build failed.
  gh run view "%RUN_ID%" --repo "%REPO%" --log-failed
  exit /b 1
)

if exist "_artifact" rmdir /s /q "_artifact"
mkdir "_artifact"
if exist "stealth_ultimate.zip" del /f /q "stealth_ultimate.zip"

echo [INFO] Downloading installable module artifact...
gh run download "%RUN_ID%" --repo "%REPO%" --name stealth-ultimate --dir "_artifact"
if errorlevel 1 (
  echo [ERROR] Artifact download failed.
  exit /b 1
)

if not exist "_artifact\stealth_ultimate.zip" (
  echo [ERROR] The artifact does not contain stealth_ultimate.zip.
  rmdir /s /q "_artifact"
  exit /b 1
)
copy /y "_artifact\stealth_ultimate.zip" "stealth_ultimate.zip" >nul
rmdir /s /q "_artifact"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $zip=(Resolve-Path 'stealth_ultimate.zip').Path; $dir=Join-Path $env:TEMP ('stealth-verify-'+[guid]::NewGuid()); Expand-Archive -LiteralPath $zip -DestinationPath $dir; $required=@('module.prop','customize.sh','post-fs-data.sh','service.sh','zygisk\arm64-v8a.so','zygisk\armeabi-v7a.so','zygisk\x86.so','zygisk\x86_64.so'); foreach($file in $required){$path=Join-Path $dir $file; if(!(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -eq 0){throw ('Missing or empty: '+$file)}}; Remove-Item -LiteralPath $dir -Recurse -Force"
if errorlevel 1 (
  echo [ERROR] Downloaded ZIP failed module validation.
  exit /b 1
)

for %%F in ("stealth_ultimate.zip") do set "ZIP_SIZE=%%~zF"
echo.
echo ========================================
echo   BUILD SUCCESSFUL
echo ========================================
echo File: %CD%\stealth_ultimate.zip
echo Size: %ZIP_SIZE% bytes
echo This is the directly installable Magisk module ZIP.
exit /b 0
