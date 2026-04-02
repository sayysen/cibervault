@echo off
setlocal enabledelayedexpansion
title Cibervault EDR Agent - Installer v3.0
color 0B

echo.
echo   ========================================================
echo        CIBERVAULT EDR AGENT INSTALLER v3.0
echo   ========================================================
echo.

:: ---- Check Admin ----
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo   [ERROR] You must run this as Administrator!
    echo.
    echo   Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)
echo   [OK] Running as Administrator
echo.

:: ---- Check exe exists ----
set "MYDIR=%~dp0"
if not exist "%MYDIR%CibervaultAgent.exe" (
    echo   [ERROR] CibervaultAgent.exe not found in:
    echo   %MYDIR%
    echo.
    echo   Make sure CibervaultAgent.exe is in the same folder.
    echo.
    pause
    exit /b 1
)
echo   [OK] Found CibervaultAgent.exe
echo.

:: ---- Show machine info ----
echo   Computer: %COMPUTERNAME%
echo.

:: ---- Step 1: Remove old agent ----
echo   [Step 1] Checking for existing agent...
sc query CibervaultAgent >nul 2>&1
if %errorLevel% equ 0 (
    echo   Found existing service. Removing it...
    net stop CibervaultAgent >nul 2>&1
    timeout /t 2 /nobreak >nul
    taskkill /f /im CibervaultAgent.exe >nul 2>&1
    timeout /t 1 /nobreak >nul
    sc delete CibervaultAgent >nul 2>&1
    timeout /t 1 /nobreak >nul
    echo   [OK] Old service removed
) else (
    echo   [OK] No existing service found
)

:: Clean old state
if exist "C:\ProgramData\Cibervault\state.json" (
    del /f /q "C:\ProgramData\Cibervault\state.json" >nul 2>&1
    echo   [OK] Old enrollment cleared
)
if exist "C:\ProgramData\Cibervault\agent.log" (
    del /f /q "C:\ProgramData\Cibervault\agent.log" >nul 2>&1
)
echo.

:: ---- Step 2: Get configuration ----
echo   [Step 2] Server Configuration
echo.

:: Check for existing config
set "USE_EXISTING=n"
if exist "C:\ProgramData\Cibervault\agent.conf" (
    echo   Found existing config file.
    set /p USE_EXISTING="  Use existing configuration? (Y/n): "
)

if /i "!USE_EXISTING!"=="y" goto :skip_config
if /i "!USE_EXISTING!"=="" goto :skip_config
if /i "!USE_EXISTING!"=="Y" goto :skip_config

echo.
echo   Enter your Cibervault SIEM server URL.
echo   Example: https://edr.cibervault.com
echo.
set "CV_SERVER="
set /p CV_SERVER="  Server URL: "
if "!CV_SERVER!"=="" (
    set "CV_SERVER=https://edr.cibervault.com"
)

echo.
echo   Enter the Agent Enrollment Secret.
echo   Find this in Dashboard - Settings - Agent Enrollment
echo.
set "CV_SECRET="
set /p CV_SECRET="  Agent Secret: "
if "!CV_SECRET!"=="" (
    echo   [ERROR] Secret is required!
    pause
    exit /b 1
)

echo.
set "CV_TLS=1"
set /p CV_TLS_INPUT="  Verify TLS? (Y/n): "
if /i "!CV_TLS_INPUT!"=="n" set "CV_TLS=0"

:: Write config
if not exist "C:\ProgramData\Cibervault" mkdir "C:\ProgramData\Cibervault"
(
    echo CV_SERVER=!CV_SERVER!
    echo CV_SECRET=!CV_SECRET!
    echo CV_VERIFY_TLS=!CV_TLS!
) > "C:\ProgramData\Cibervault\agent.conf"

echo.
echo   [OK] Config saved
echo.

:skip_config

:: ---- Step 3: Copy files ----
echo   [Step 3] Installing files...

if not exist "C:\Program Files\Cibervault" mkdir "C:\Program Files\Cibervault"
copy /y "%MYDIR%CibervaultAgent.exe" "C:\Program Files\Cibervault\CibervaultAgent.exe" >nul
echo   [OK] Agent copied to C:\Program Files\Cibervault\
echo.

:: ---- Step 4: Install service ----
echo   [Step 4] Installing Windows service...

sc create CibervaultAgent binPath= "\"C:\Program Files\Cibervault\CibervaultAgent.exe\" --service" start= auto DisplayName= "Cibervault EDR Agent" >nul 2>&1
if %errorLevel% equ 0 (
    echo   [OK] Service created
) else (
    echo   [!!] Service creation issue - may already exist
)

sc description CibervaultAgent "Cibervault EDR - Active response and process monitoring" >nul 2>&1
sc failure CibervaultAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000 >nul 2>&1
sc config CibervaultAgent obj= LocalSystem >nul 2>&1
echo   [OK] Service configured (auto-start, auto-restart)
echo.

:: ---- Step 5: Start service ----
echo   [Step 5] Starting service...
net start CibervaultAgent >nul 2>&1
timeout /t 4 /nobreak >nul

sc query CibervaultAgent | findstr "RUNNING" >nul 2>&1
if %errorLevel% equ 0 (
    echo   [OK] Service is RUNNING
) else (
    echo   [!!] Service not running yet. Check log file.
)
echo.

:: ---- Step 6: Verify ----
echo   [Step 6] Verifying...
timeout /t 3 /nobreak >nul

if exist "C:\ProgramData\Cibervault\agent.log" (
    findstr "Enrolled" "C:\ProgramData\Cibervault\agent.log" >nul 2>&1
    if !errorLevel! equ 0 (
        echo   [OK] Agent enrolled successfully
    ) else (
        findstr "Resumed" "C:\ProgramData\Cibervault\agent.log" >nul 2>&1
        if !errorLevel! equ 0 (
            echo   [OK] Agent resumed
        ) else (
            echo   [!!] Enrollment pending
        )
    )
    findstr "Smart mode active" "C:\ProgramData\Cibervault\agent.log" >nul 2>&1
    if !errorLevel! equ 0 (
        echo   [OK] Process Monitor active
    )
) else (
    echo   [!!] Log not created yet
)

:: ---- Done ----
echo.
echo   ========================================================
echo        INSTALLATION COMPLETE
echo   ========================================================
echo.
echo   Install:  C:\Program Files\Cibervault\
echo   Config:   C:\ProgramData\Cibervault\agent.conf
echo   Log:      C:\ProgramData\Cibervault\agent.log
echo   Service:  CibervaultAgent (auto-start)
echo.

pause
