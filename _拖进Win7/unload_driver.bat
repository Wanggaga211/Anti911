@echo off
setlocal
title Anti911 Driver Unloader

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Please run as Administrator.
    pause
    exit /b 1
)

echo Stopping driver...
sc stop KAnti911
ping -n 3 127.0.0.1 >nul

echo Deleting service...
sc delete KAnti911
ping -n 2 127.0.0.1 >nul

echo Verify...
sc query KAnti911
echo.
echo [DONE] If "1060" appears above, the service is gone - that is normal.
pause
