Function Start-Executable
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [IO.FileInfo]$Executable,
        [String[]]$Arguments
    )

    Begin
    {
        $ProcessInfo = New-Object -TypeName Diagnostics.ProcessStartInfo -ErrorAction:$ErrorActionPreference
        $ProcessInfo.FileName = $Executable.FullName
        If (![String]::IsNullOrEmpty($Arguments)) { $ProcessInfo.Arguments = $Arguments }
        $ProcessInfo.CreateNoWindow = $true
        $ProcessInfo.WindowStyle = 'Hidden'
        $ProcessInfo.UseShellExecute = $false
        $ProcessRun = New-Object -TypeName Diagnostics.Process -ErrorAction:$ErrorActionPreference
        $ProcessRun.StartInfo = $ProcessInfo
    }
    Process
    {
        [Void]$ProcessRun.Start()
        $ProcessRun.WaitForExit()
        $ProcessRun.ExitCode
    }
    End
    {
        If ($null -ne $ProcessRun) { $ProcessRun.Dispose() }
    }
}