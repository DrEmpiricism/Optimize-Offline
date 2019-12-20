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
        $StartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo -ErrorAction:$ErrorActionPreference
        $StartInfo.FileName = $Executable.FullName
        If (![String]::IsNullOrEmpty($Arguments)) { $StartInfo.Arguments = $Arguments }
        $StartInfo.CreateNoWindow = $true
        $StartInfo.WindowStyle = 'Hidden'
        $StartInfo.UseShellExecute = $false
        $Process = New-Object -TypeName System.Diagnostics.Process -ErrorAction:$ErrorActionPreference
        $Process.StartInfo = $StartInfo
    }
    Process
    {
        [Void]$Process.Start()
        $Process.WaitForExit()
        $Process.ExitCode
    }
    End
    {
        If ($null -ne $Process) { $Process.Dispose() }
    }
}