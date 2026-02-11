@echo off
title Subnet Scanner
cd /d "%~dp0"

echo.
echo  ========================================
echo   Subnet Scanner
echo  ========================================
echo.

:: ── Check Python ──────────────────────────────────────────────────
where python >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python is not installed or not in PATH.
    echo  Download it from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  [OK] %PYVER%

:: ── Check Nmap ────────────────────────────────────────────────────
where nmap >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Nmap is not installed or not in PATH.
    echo  Download it from https://nmap.org/download.html
    echo  Make sure to check "Add Nmap to PATH" during installation.
    echo.
    pause
    exit /b 1
)

for /f "tokens=1-3" %%a in ('nmap --version 2^>^&1 ^| findstr /i "Nmap version"') do set NMAPVER=%%a %%b %%c
echo  [OK] %NMAPVER%

:: ── Create venv if it doesn't exist ───────────────────────────────
if not exist ".venv\Scripts\activate.bat" (
    echo.
    echo  [*] Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo  [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  [OK] Virtual environment created.
)

:: ── Activate venv ─────────────────────────────────────────────────
call .venv\Scripts\activate.bat

:: ── Install / update requirements ─────────────────────────────────
echo  [*] Checking dependencies...
pip install -r requirements.txt --quiet --disable-pip-version-check 2>nul
if errorlevel 1 (
    echo  [WARN] Some packages may have failed to install.
    echo  Attempting to continue...
)
echo  [OK] All dependencies installed.
echo.

:: ── Start server ──────────────────────────────────────────────────
echo  ----------------------------------------
echo   Starting Subnet Scanner...
echo   URL:  http://localhost:5000
echo   Stop: Press Ctrl+C
echo  ----------------------------------------
echo.

:: Open browser after a short delay
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:5000"

python app.py
pause
