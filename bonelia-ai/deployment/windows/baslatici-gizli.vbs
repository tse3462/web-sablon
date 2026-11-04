' Hidden launcher: starts the BONELIA home server + phone panel with NO visible window.
' Used by the "BONELIA AI" logon task so nothing flashes on screen at login.
Dim sh, dir
Set sh = CreateObject("WScript.Shell")
dir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
sh.Run "cmd /c """ & dir & "BONELIA-Baslat.bat"" /quiet", 0, False
