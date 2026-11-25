@echo off
setlocal
title Anti911 Driver Loader

if not exist "%~dp0KAnti911.sys" (
    echo [ERROR] KAnti911.sys not found in %~dp0
    echo         Put this bat next to the .sys file.
    pause
    exit /b 1
)

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Please run as Administrator.
    pause
    exit /b 1
)

echo [1/4] Clean previous service...
sc stop KAnti911 >nul 2>&1
sc delete KAnti911 >nul 2>&1
ping -n 2 127.0.0.1 >nul

echo [2/4] Create service...
sc create KAnti911 type= kernel start= demand error= normal binPath= "%~dp0KAnti911.sys"
if errorlevel 1 (
    echo [ERROR] sc create failed. code=%errorlevel%
    pause
    exit /b 1
)

echo [3/4] Start driver...
sc start KAnti911
set RC=%errorlevel%

echo [4/4] Query status...
sc query KAnti911

echo.
if "%RC%"=="0" (
    echo [OK] Driver loaded. Device: \\.\KAnti911
    echo      Now run Test.exe, then Anti911.exe or the memory manager.
) else (
    echo [FAIL] sc start returned %RC%
    echo   577  = image signature not verified  -- testsigning not active
    echo   1275 = driver blocked by policy      -- recheck testsigning or use F8 mode
    echo   127  = file not found                -- check binPath
    echo   1058 = service disabled              -- check start= type
    echo.
    echo   Fix: bcdedit /set testsigning on   then reboot.
)
echo.
pause
