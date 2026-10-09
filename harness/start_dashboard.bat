@echo off
title NetDecoy DNS Controller Dashboard
cd /d "%~dp0"
echo Starting NetDecoy DNS Controller Dashboard...
python dns_dashboard.py
pause
