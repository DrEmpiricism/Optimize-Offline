Function Invoke-Cleanup
{
    [CmdletBinding()]
    Param
    (
        [ValidateSet('Install', 'Boot', 'Recovery')]
        [String]$Image = 'Install'
    )

    $MountPath = Switch ($PSBoundParameters.Image)
    {
        'Install' { $InstallMount; Break }
        'Boot' { $BootMount; Break }
        'Recovery' { $RecoveryMount; Break }
    }

    @("$MountPath\Windows\WinSxS\Temp\PendingDeletes\*", "$MountPath\Windows\WinSxS\Temp\TransformerRollbackData\*", "$MountPath\Windows\WinSxS\ManifestCache\*.bin") | Purge -Force -ErrorAction Ignore
    @("$MountPath\Windows\INF\*.log", "$MountPath\Windows\CbsTemp\*", "$MountPath\PerfLogs", ("$MountPath\" + '$Recycle.Bin')) | Purge -ErrorAction Ignore
}