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

    @((GetPath -Path $MountPath -Child "Windows\WinSxS\Temp\PendingDeletes\*"), (GetPath -Path $MountPath -Child "Windows\WinSxS\Temp\TransformerRollbackData\*"), (GetPath -Path $MountPath -Child "Windows\WinSxS\ManifestCache\*.bin")) | Purge -Force -ErrorAction Ignore
    @((GetPath -Path $MountPath -Child PerfLogs), (GetPath -Path $MountPath -Child "Windows\INF\*.log"), (GetPath -Path $MountPath -Child "Windows\CbsTemp\*"), (GetPath -Path $MountPath -Child PerfLogs), ("$MountPath\" + '$Recycle.Bin')) | Purge -ErrorAction Ignore
}