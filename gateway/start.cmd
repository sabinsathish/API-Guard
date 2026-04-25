@echo off
echo Clearing port 3000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3000 " ^| findstr "LISTENING" 2^>nul') do (
    taskkill /F /PID %%a >nul 2>&1
    echo Killed existing process on port 3000
)
timeout /t 1 /nobreak >nul
echo Starting Secure API Gateway...
node server.js
