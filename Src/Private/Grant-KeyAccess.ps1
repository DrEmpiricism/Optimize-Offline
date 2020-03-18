Function Grant-KeyAccess
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        [String]$SubKey
    )

    Begin
    {
        $Access = @{
            FullControl      = [Security.AccessControl.RegistryRights]::FullControl
            ContainerInherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit
            NoPropagation    = [Security.AccessControl.PropagationFlags]::None
            Allow            = [Security.AccessControl.AccessControlType]::Allow
        }
        'SeTakeOwnershipPrivilege' | Grant-Privilege
    }
    Process
    {
        $KeyPath = $SubKey.Insert(0, 'HKLM:\')
        If (Test-Path -LiteralPath $KeyPath) { $KeyOwner = [Security.Principal.NTAccount](Get-Item -LiteralPath $KeyPath -Force -ErrorAction SilentlyContinue).GetAccessControl().Owner }
        $Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::TakeOwnership)
        $ACL = $Key.GetAccessControl([Security.AccessControl.AccessControlSections]::None)
        $Admin = (New-Object -TypeName Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount])
        $ACL.SetOwner($Admin)
        $Key.SetAccessControl($ACL)
        $ACL = $Key.GetAccessControl()
        $ACL.SetAccessRule((New-Object -TypeName Security.AccessControl.RegistryAccessRule($Admin, $Access.FullControl, $Access.ContainerInherit, $Access.NoPropagation, $Access.Allow)))
        $Key.SetAccessControl($ACL)
        $Key.Close()
        $Key.Dispose()
        [GC]::Collect()
        If ($KeyOwner -ne $Admin)
        {
            $ACL = Get-Acl -Path $KeyPath -ErrorAction SilentlyContinue
            $ACL.SetOwner($KeyOwner)
            'SeRestorePrivilege' | Grant-Privilege
            $ACL | Set-Acl -Path $KeyPath -ErrorAction SilentlyContinue
            'SeRestorePrivilege' | Grant-Privilege -Disable
        }
    }
    End
    {
        'SeTakeOwnershipPrivilege' | Grant-Privilege -Disable
    }
}