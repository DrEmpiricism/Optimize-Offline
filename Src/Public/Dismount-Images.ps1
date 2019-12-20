Function Dismount-Images
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        $ProgressPreference = 'SilentlyContinue'
        Set-ErrorAction SilentlyContinue
        $QueryHives = Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-Offline')
        $MountPath = @()
        $MountPath += (Get-WindowsImage -Mounted | Where-Object -Property ImagePath -Match winre.wim | Select-Object -ExpandProperty MountPath)
        $MountPath += (Get-WindowsImage -Mounted | Where-Object -Property ImagePath -Match install.wim | Select-Object -ExpandProperty MountPath)
        $MountPath += (Get-WindowsImage -Mounted | Where-Object -Property ImagePath -Match boot.wim | Select-Object -ExpandProperty MountPath)
        If (RegHives -Test) { RegHives -Unload }
    }
    Process
    {
        If ($QueryHives)
        {
            [GC]::Collect()
            $QueryHives | ForEach-Object -Process { [Void](StartExe $REG -Arguments ('UNLOAD {0}' -f $PSItem) -ErrorAction:$ErrorActionPreference) }
        }
        $MountPath.ForEach{ [Void](Dismount-WindowsImage -Path $PSItem -Discard -ErrorAction:$ErrorActionPreference) }
    }
    End
    {
        If (!(Get-WindowsImage -Mounted)) { [Void](Clear-WindowsCorruptMountPoint) }
        Set-ErrorAction -Restore
    }
}