Function Dismount-Images
{
    [CmdletBinding()]
    Param ()

    If (Get-OfflineHives -Test) { Get-OfflineHives -Unload }
    Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-Offline') | ForEach-Object { Start-Executable -Executable "$Env:SystemRoot\System32\reg.exe" -Arguments ('UNLOAD {0}' -f $($_)) }
    $MountPath = @()
    If ((Get-WindowsImage -Mounted).ImagePath -match "winre.wim") { $MountPath += (Get-WindowsImage -Mounted).MountPath | Where-Object { $_ -like "*Recovery*" } }
    If ((Get-WindowsImage -Mounted).ImagePath -match "install.wim") { $MountPath += (Get-WindowsImage -Mounted).MountPath | Where-Object { $_ -like "*Install*" } }
    If ((Get-WindowsImage -Mounted).ImagePath -match "boot.wim") { $MountPath += (Get-WindowsImage -Mounted).MountPath | Where-Object { $_ -like "*Boot*" } }
    $MountPath.ForEach{ [void](Dismount-WindowsImage -Path $_ -Discard) }
    [void](Clear-WindowsCorruptMountPoint)
}