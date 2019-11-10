Function Dismount-Images
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        $ProgressPreference = 'SilentlyContinue'
    }
    Process
    {
        If (RegHives -Test) { RegHives -Unload }
        Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-Offline') | ForEach-Object -Process { [Void](RunExe $REG -Arguments ('UNLOAD {0}' -f $($_))) }
        $MountPath = [Collections.Generic.List[Object]]::New()
        $MountPath.Add((Get-WindowsImage -Mounted | Where-Object -Property ImagePath -Match winre.wim | Select-Object -ExpandProperty MountPath))
        $MountPath.Add((Get-WindowsImage -Mounted | Where-Object -Property ImagePath -Match install.wim | Select-Object -ExpandProperty MountPath))
        $MountPath.Add((Get-WindowsImage -Mounted | Where-Object -Property ImagePath -Match boot.wim | Select-Object -ExpandProperty MountPath))
        $MountPath | ForEach-Object -Process { [Void](Dismount-WindowsImage -Path $($_) -Discard) }
    }
    End
    {
        If (!(Get-WindowsImage -Mounted)) { [Void](Clear-WindowsCorruptMountPoint) }
    }
}