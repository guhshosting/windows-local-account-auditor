@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b %errorlevel%
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
if errorlevel 1 exit /b %errorlevel%
cmake --build build --config Release
exit /b %errorlevel%
