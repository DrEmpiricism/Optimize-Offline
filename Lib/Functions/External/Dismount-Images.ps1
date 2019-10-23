Function Dismount-Images
{
    [CmdletBinding()]
    Param ()

    If (RegHives -Test) { RegHives -Unload }
    Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-Offline') | ForEach-Object { RunExe $REG -Arguments ('UNLOAD {0}' -f $($_)) }
    $MountPath = @()
    If ((Get-WindowsImage -Mounted).ImagePath -match "winre.wim") { $MountPath += (Get-WindowsImage -Mounted).MountPath | Where-Object { $_ -like "*Recovery*" } }
    If ((Get-WindowsImage -Mounted).ImagePath -match "install.wim") { $MountPath += (Get-WindowsImage -Mounted).MountPath | Where-Object { $_ -like "*Install*" } }
    If ((Get-WindowsImage -Mounted).ImagePath -match "boot.wim") { $MountPath += (Get-WindowsImage -Mounted).MountPath | Where-Object { $_ -like "*Boot*" } }
    $MountPath.ForEach{ [Void](Dismount-WindowsImage -Path $_ -Discard) }
    [Void](Clear-WindowsCorruptMountPoint)
}