@echo off
REM One-time setup for the PhishAlert canary server (needs Node.js + a free Cloudflare account)
cd /d "%~dp0"
node canary-server\deploy-canary.js
pause
