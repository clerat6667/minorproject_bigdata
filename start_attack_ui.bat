@echo off
echo ======================================================================
echo    CYBER RANGE ATTACK SIMULATOR & THREAT GENERATOR LAUNCHER
echo    Department of AI & Data Science - Big Data Cybersecurity Platform
echo ======================================================================
echo.
echo Starting Red Team Attack Initiator on http://localhost:8050 ...
echo Target Application: http://localhost:3000 (OWASP Juice Shop)
echo SOC Dashboard:      http://localhost:8000
echo.
python attack_lab\server.py
pause
