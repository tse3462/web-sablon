@echo off
rem Updates BONELIA AI from GitHub: server + background agent, in one double-click.
rem The new code is fetched FIRST, while the server keeps running: if GitHub cannot be reached
rem (no internet, DNS, login), nothing is stopped and the full answer of git is shown with a hint.
rem Only then the server is stopped, reinstalled, and started again with the background agent.
setlocal
cd /d "%~dp0..\.."
set "PULLOUT=%TEMP%\bonelia-git-pull.txt"
set "TRY=0"

:pull
set /a TRY+=1
git pull > "%PULLOUT%" 2>&1
if not errorlevel 1 goto pulled
if %TRY% geq 3 goto pullfailed
echo GitHub'a ulasilamadi, 10 saniye sonra tekrar deneniyor - deneme %TRY%/3
timeout /t 10 /nobreak >nul
goto pull

:pullfailed
echo.
echo ================================================================
echo  GUNCELLEME YAPILAMADI / UPDATE NICHT MOEGLICH
echo  BONELIA eski surumle calismaya devam ediyor.
echo ================================================================
echo --- git cevabi / Antwort von git ---
type "%PULLOUT%"
echo ------------------------------------
findstr /i /c:"resolve host" /c:"Could not connect" /c:"timed out" /c:"Failed to connect" "%PULLOUT%" >nul && echo SEBEP: Bu bilgisayar su an GitHub'a ulasamiyor - internet veya DNS. Tarayicida github.com aciliyor mu? Birkac dakika sonra tekrar deneyin.
findstr /i /c:"Authentication failed" /c:"could not read Username" /c:"403" /c:"Repository not found" "%PULLOUT%" >nul && echo SEBEP: GitHub girisi gerekiyor. GitHub Desktop'ta oturum acin veya Git Credential Manager ile giris yapin, sonra tekrar deneyin.
findstr /i /c:"local changes" /c:"would be overwritten" /c:"divergent" /c:"not possible to fast-forward" "%PULLOUT%" >nul && echo SEBEP: Bu klasorde elle degismis dosyalar var. Ekranin fotografini Claude'a gonderin.
rem An earlier, older version of this script stopped the server before pulling: make sure it runs.
call "%~dp0BONELIA-Server-Baslat.bat" /quiet
call "%~dp0BONELIA-Panel-Baslat.bat" /quiet
if not defined CI pause
endlocal & exit /b 1

:pulled
type "%PULLOUT%"
call "%~dp0BONELIA-Server-Durdur.bat"

call ".venv\Scripts\activate.bat"
pip install -e ".[server]"

rem Bring the server AND the phone panel back up in the background with the new code.
rem (Durdur above stopped both, since they are the same server program; both must
rem be restarted or the panel keeps serving the old version and the old phone link.)
call "%~dp0BONELIA-Server-Baslat.bat" /quiet
call "%~dp0BONELIA-Panel-Baslat.bat" /quiet

rem Restart the background agent on the new code. It runs with admin rights, so this needs
rem one "Ja/Yes" (UAC). BONELIA-Ajan-Onar stops every old agent process first, so exactly one
rem agent runs afterwards (two agents at once would double some actions).
call "%~dp0BONELIA-Ajan-Onar.bat"

echo.
echo Guncelleme bitti / Update fertig. Sunucu, telefon paneli ve arka plan ajani
echo guncel surumle calisiyor. Telefon adresi: C:\BoneliaAI\server-data\panel-url.txt
echo (Server, Panel und Hintergrund-Agent laufen mit der neuen Version.)
pause
endlocal
