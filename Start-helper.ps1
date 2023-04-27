$scriptPath = '.\Start-Optimize.ps1'
$process = Start-Process -FilePath "powershell.exe" -ArgumentList ("-NoExit", "-ExecutionPolicy Bypass", "-File `"$scriptPath`"") -PassThru
$process | Wait-Process

& .\Remove_Failure_no_prompts.cmd