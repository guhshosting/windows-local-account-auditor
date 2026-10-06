@echo off
"C:\Program Files\Cppcheck\cppcheck.exe" --enable=warning,style,performance,portability --error-exitcode=1 --std=c++17 --platform=win64 --inline-suppr --suppress=missingIncludeSystem --library=windows -Isrc src tests
exit /b %errorlevel%
