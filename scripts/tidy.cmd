@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b %errorlevel%
"C:\Program Files\LLVM\bin\clang-tidy.exe" src/core.cpp src/windows.cpp src/main.cpp tests/tests.cpp --warnings-as-errors=* --checks=-*,clang-analyzer-*,bugprone-*,performance-* -- -std=c++17 -Isrc -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0A00
exit /b %errorlevel%
