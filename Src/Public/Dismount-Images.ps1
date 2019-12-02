Function Dismount-Images
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        $ProgressPreference = 'SilentlyContinue'
        If (RegHives -Test) { RegHives -Unload }
    }
    Process
    {
        Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-Offline') | ForEach-Object -Process { [Void](RunExe $REG -Arguments ('UNLOAD {0}' -f $($_))) }
        $MountPath = @()
        $MountPath += Get-WindowsImage -Mounted | Where-Object -Property ImagePath -Match winre.wim | Select-Object -ExpandProperty MountPath
        $MountPath += Get-WindowsImage -Mounted | Where-Object -Property ImagePath -Match install.wim | Select-Object -ExpandProperty MountPath
        $MountPath += Get-WindowsImage -Mounted | Where-Object -Property ImagePath -Match boot.wim | Select-Object -ExpandProperty MountPath
        $MountPath.ForEach{ [Void](Dismount-WindowsImage -Path $PSItem -Discard) }
    }
    End
    {
        If (!(Get-WindowsImage -Mounted)) { [Void](Clear-WindowsCorruptMountPoint) }
    }
}