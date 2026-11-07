' Runs a .bat with NO visible window and waits for it (used by the weekly backup task).
' Usage: wscript.exe gizli-calistir.vbs "C:\path\script.bat" /auto
Dim sh, cmd, i
Set sh = CreateObject("WScript.Shell")
cmd = "cmd /c """"" & WScript.Arguments(0) & """"
For i = 1 To WScript.Arguments.Count - 1
  cmd = cmd & " " & WScript.Arguments(i)
Next
cmd = cmd & """"
sh.Run cmd, 0, True
