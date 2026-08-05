@echo off
REM Native Windows build with MSVC (Developer Command Prompt / vsdevcmd)
REM Output: build\openhicos-pkcs11-windows-x86_64.so
REM
REM Prerequisites:
REM   - Visual Studio with C++ workload
REM   - Winscard.lib (Windows SDK)

setlocal
set OUT=build
set OBJDIR=.obj
set ARCH=x86_64
if /I "%VSCMD_ARG_TGT_ARCH%"=="arm64" set ARCH=arm64
if /I "%PROCESSOR_ARCHITECTURE%"=="ARM64" if "%VSCMD_ARG_TGT_ARCH%"=="" set ARCH=arm64

set LIBNAME=openhicos-pkcs11-windows-%ARCH%.so
set TARGET=%OUT%\%LIBNAME%

if not exist %OUT% mkdir %OUT%
if not exist %OBJDIR% mkdir %OBJDIR%

set CFLAGS=/nologo /O2 /W3 /Iinclude /Ipkcs11 /D_CRT_SECURE_NO_WARNINGS
set SRCS=pkcs11\module.c pkcs11\oh_pcsc.c pkcs11\oh_apdu.c pkcs11\oh_der.c pkcs11\oh_sha.c pkcs11\oh_p15.c

echo Compiling...
cl %CFLAGS% /c %SRCS% /Fo%OBJDIR%\
if errorlevel 1 exit /b 1

echo Linking %TARGET% ...
link /nologo /DLL /OUT:%TARGET% /DEF:pkcs11\openhicos.def ^
  %OBJDIR%\module.obj %OBJDIR%\oh_pcsc.obj %OBJDIR%\oh_apdu.obj ^
  %OBJDIR%\oh_der.obj %OBJDIR%\oh_sha.obj %OBJDIR%\oh_p15.obj ^
  Winscard.lib
if errorlevel 1 exit /b 1

echo built %TARGET%
endlocal
