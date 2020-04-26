Function Dismount-Images
{
    [CmdletBinding()]
    Param ()

    If (Get-WindowsImage -Mounted)
    {
        $Host.UI.RawUI.WindowTitle = $OptimizeData.ActiveMountPoints
        Write-Host $OptimizeData.ActiveMountPoints -ForegroundColor Cyan
        RegHives -Unload
        If (Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-Offline'))
        {
            [GC]::Collect()
            Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-Offline') | ForEach-Object -Process { [Void](StartExe $REG -Arguments ('UNLOAD {0}' -f $PSItem)) }
        }
        Get-WindowsImage -Mounted | ForEach-Object -Process {
            If ($PSItem.ImagePath -match 'boot.wim' -or $PSItem.ImagePath -match 'winre.wim' -or $PSItem.ImagePath -match 'install.wim') { [Void](Dismount-WindowsImage -Path $PSItem.MountPath -Discard) }
        }
    }
}