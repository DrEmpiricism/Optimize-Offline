Function Start-Executable
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [IO.FileInfo]$Executable,
        [string[]]$Arguments,
        [switch]$PassThru
    )

    Begin
    {
        $StartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        $StartInfo.FileName = $Executable.FullName
        $StartInfo.Arguments = $Arguments
        $StartInfo.CreateNoWindow = $true
        $StartInfo.WindowStyle = 'Hidden'
        $StartInfo.UseShellExecute = $false
        $Process = New-Object -TypeName System.Diagnostics.Process
        $Process.StartInfo = $StartInfo
    }
    Process
    {
        [void]$Process.Start()
        $Process.WaitForExit()
        If ($PassThru.IsPresent) { $Process.ExitCode }
    }
}