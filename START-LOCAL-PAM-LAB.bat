@echo off
TITLE Authentic Local PAM Lab
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0START-LOCAL-PAM-LAB.ps1"
pause
