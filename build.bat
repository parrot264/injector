@echo off
echo [+] PE Injector Build Script
echo.

REM Try to find Visual Studio Build Tools
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VS_PATH=%%i"
    )
)

if defined VS_PATH (
    echo [+] Found Visual Studio at: %VS_PATH%
    call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto :compile_vs
)

REM Try to find MinGW
where gcc >nul 2>&1
if %errorlevel% == 0 (
    echo [+] Found MinGW/GCC
    goto :compile_mingw
)

echo [-] No suitable compiler found!
echo [*] Please install one of the following:
echo     - Visual Studio Build Tools
echo     - MinGW-w64
echo     - Dev-C++ with MinGW
goto :end

:compile_vs
echo [*] Compiling with Visual Studio...
cl /EHsc /O2 fun.cpp /Fe:pe_injector.exe /link kernel32.lib user32.lib
if %errorlevel% == 0 (
    echo [+] Injector compiled successfully!
) else (
    echo [-] Injector compilation failed!
    goto :end
)

cl /EHsc /O2 /LD test_dll.cpp /Fe:test_dll.dll /link kernel32.lib user32.lib
if %errorlevel% == 0 (
    echo [+] Test DLL compiled successfully!
) else (
    echo [-] Test DLL compilation failed!
)

cl /EHsc /O2 simple_target.cpp /Fe:simple_target.exe /link kernel32.lib user32.lib
if %errorlevel% == 0 (
    echo [+] Simple target compiled successfully!
) else (
    echo [-] Simple target compilation failed!
)

cl /EHsc /O2 debug_processes.cpp /Fe:debug_processes.exe /link kernel32.lib
if %errorlevel% == 0 (
    echo [+] Debug tool compiled successfully!
) else (
    echo [-] Debug tool compilation failed!
)
goto :success

:compile_mingw
echo [*] Compiling with MinGW...
gcc -std=c++11 -Wall -O2 -o pe_injector.exe fun.cpp -static-libgcc -static-libstdc++
if %errorlevel% == 0 (
    echo [+] Injector compiled successfully!
) else (
    echo [-] Injector compilation failed!
    goto :end
)

gcc -std=c++11 -Wall -O2 -shared -o test_dll.dll test_dll.cpp
if %errorlevel% == 0 (
    echo [+] Test DLL compiled successfully!
) else (
    echo [-] Test DLL compilation failed!
)

gcc -std=c++11 -Wall -O2 -o simple_target.exe simple_target.cpp -static-libgcc -static-libstdc++
if %errorlevel% == 0 (
    echo [+] Simple target compiled successfully!
) else (
    echo [-] Simple target compilation failed!
)
goto :success

:success
echo.
echo [+] Build completed!
echo [+] Usage: pe_injector.exe ^<target_executable^> ^<section_name^> ^<dll_path^>
echo [+] Example: pe_injector.exe notepad.exe .inject test_dll.dll
echo.
echo [*] To test:
echo    1. Start notepad.exe
echo    2. Run: pe_injector.exe notepad.exe .inject test_dll.dll
echo.

:end
pause
