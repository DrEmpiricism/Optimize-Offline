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
            FullControl      = [System.Security.AccessControl.RegistryRights]::FullControl
            ContainerInherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
            NoPropagation    = [System.Security.AccessControl.PropagationFlags]::None
            Allow            = [System.Security.AccessControl.AccessControlType]::Allow
        }
        'SeTakeOwnershipPrivilege' | Grant-Privilege
    }
    Process
    {
        $Key = $SubKey.Insert(0, 'HKLM:\')
        $KeyOwner = [System.Security.Principal.NTAccount](Get-Item -LiteralPath $Key -Force -ErrorAction SilentlyContinue).GetAccessControl().Owner
        $Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
        $ACL = $Key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
        $Admin = (New-Object -TypeName System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount])
        $ACL.SetOwner($Admin)
        $Key.SetAccessControl($ACL)
        $ACL = $Key.GetAccessControl()
        $ACL.SetAccessRule((New-Object -TypeName System.Security.AccessControl.RegistryAccessRule($Admin, $Access.FullControl, $Access.ContainerInherit, $Access.NoPropagation, $Access.Allow)))
        $Key.SetAccessControl($ACL)
        $Key.Close()
        $Key.Dispose()
        [GC]::Collect()
        $Key = $SubKey.Insert(0, 'HKLM:\')
        $ACL = Get-Acl -Path $Key -ErrorAction:$ErrorActionPreference
        $ACL.SetOwner($KeyOwner)
        'SeRestorePrivilege' | Grant-Privilege
        $ACL | Set-Acl -Path $Key -ErrorAction:$ErrorActionPreference
        'SeRestorePrivilege' | Grant-Privilege -Disable
    }
    End
    {
        'SeTakeOwnershipPrivilege' | Grant-Privilege -Disable
    }
}