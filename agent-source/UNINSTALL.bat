@echo off
setlocal enabledelayedexpansion
title Cibervault EDR Agent - Uninstaller
color 0C

echo.
echo   ========================================================
echo        CIBERVAULT EDR AGENT UNINSTALLER
echo   ========================================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo   [ERROR] Run as Administrator!
    pause
    exit /b 1
)

set /p CONFIRM="  Remove Cibervault Agent completely? (y/N): "
if /i not "!CONFIRM!"=="y" (
    echo   Cancelled.
    pause
    exit /b 0
)

echo.
echo   Stopping service...
net stop CibervaultAgent >nul 2>&1
timeout /t 2 /nobreak >nul
taskkill /f /im CibervaultAgent.exe >nul 2>&1
timeout /t 1 /nobreak >nul

echo   Removing service...
sc delete CibervaultAgent >nul 2>&1
timeout /t 1 /nobreak >nul
echo   [OK] Service removed

echo   Removing program files...
if exist "C:\Program Files\Cibervault" (
    rmdir /s /q "C:\Program Files\Cibervault" >nul 2>&1
    echo   [OK] Program files removed
)

echo.
set /p REMOVEDATA="  Also remove config and logs? (y/N): "
if /i "!REMOVEDATA!"=="y" (
    if exist "C:\ProgramData\Cibervault" (
        rmdir /s /q "C:\ProgramData\Cibervault" >nul 2>&1
        echo   [OK] Data removed
    )
) else (
    echo   Config preserved at C:\ProgramData\Cibervault\
)

echo.
echo   ========================================================
echo        UNINSTALL COMPLETE
echo   ========================================================
echo.

pause
