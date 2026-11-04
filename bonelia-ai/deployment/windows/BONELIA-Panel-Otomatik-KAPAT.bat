@echo off
set "F=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\BONELIA-AI-Panel.bat"
if exist "%F%" (del "%F%" & echo Panel otomatik baslatma KAPALI / Autostart AUS.) else (echo Zaten kapali / bereits aus.)
if not defined CI timeout /t 4 >nul
