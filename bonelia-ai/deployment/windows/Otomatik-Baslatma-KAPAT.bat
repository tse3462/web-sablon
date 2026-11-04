@echo off
set "F=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\BONELIA-AI-Server.bat"
if exist "%F%" (del "%F%" & echo Otomatik baslatma KAPALI / Autostart AUS.) else (echo Otomatik baslatma zaten kapali / bereits aus.)
if not defined CI timeout /t 4 >nul
