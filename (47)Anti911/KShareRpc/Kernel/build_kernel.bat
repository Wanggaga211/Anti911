@echo off
rem Build KShareRpc.sys with VS2019 x64 + WDK 10.0.22000 (headers and km libs).
rem Pure ASCII only: cmd.exe parses .bat in the OEM code page.
rem
rem This script only proves the code compiles and links. LOADING it needs a
rem test-signing VM (or disabled driver signature enforcement) - never load an
rem unsigned driver on a machine you care about.
setlocal

set WDK=C:\Program Files (x86)\Windows Kits\10
set WDKVER=10.0.22000.0

call "D:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo [build] vcvars64.bat not found - edit the call line of build_kernel.bat
    exit /b 1
)

cd /d "%~dp0"

echo [build] cl ...
cl /nologo /c /kernel /GS- /utf-8 /wd4819 /D_AMD64_ ^
   /I"%WDK%\Include\%WDKVER%\km" ^
   /I"%WDK%\Include\%WDKVER%\km\crt" ^
   /I"%WDK%\Include\%WDKVER%\shared" ^
   KShareRpc.c
if errorlevel 1 exit /b 1

echo [build] link ...
link /nologo /DRIVER /SUBSYSTEM:NATIVE /MACHINE:X64 /OUT:KShareRpc.sys /ENTRY:DriverEntry ^
   KShareRpc.obj ntoskrnl.lib hal.lib ^
   /LIBPATH:"%WDK%\Lib\%WDKVER%\km\x64" /NODEFAULTLIB
if errorlevel 1 exit /b 1

echo [build] OK - KShareRpc.sys
echo [build] note: not loaded/tested here; see README in this folder
endlocal
