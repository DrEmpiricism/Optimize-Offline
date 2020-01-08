Function Dismount-Images
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        $ProgressPreference = 'SilentlyContinue'
        $MountPath = @()
        $MountPath += (Get-WindowsImage -Mounted | Where-Object -Property ImagePath -Match winre.wim | Select-Object -ExpandProperty MountPath)
        $MountPath += (Get-WindowsImage -Mounted | Where-Object -Property ImagePath -Match install.wim | Select-Object -ExpandProperty MountPath)
        $MountPath += (Get-WindowsImage -Mounted | Where-Object -Property ImagePath -Match boot.wim | Select-Object -ExpandProperty MountPath)
    }
    Process
    {
        If (RegHives -Test) { RegHives -Unload }
        If (Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-Offline') -ErrorAction SilentlyContinue)
        {
            [GC]::Collect()
            Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-Offline') -ErrorAction SilentlyContinue | ForEach-Object -Process { [Void](StartExe $REG -Arguments ('UNLOAD {0}' -f $PSItem) -ErrorAction SilentlyContinue) }
        }
        $MountPath.ForEach{ [Void](Dismount-WindowsImage -Path $PSItem -Discard -ErrorAction SilentlyContinue) }
    }
    End
    {
        If (!(Get-WindowsImage -Mounted)) { [Void](Clear-WindowsCorruptMountPoint) }
    }
}