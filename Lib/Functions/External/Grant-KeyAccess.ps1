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
        'SeTakeOwnershipPrivilege', 'SeRestorePrivilege' | Grant-Privilege
    }
    Process
    {
        $Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
        $ACL = $Key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
        $Admin = ((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]))
        $ACL.SetOwner($Admin)
        $Key.SetAccessControl($ACL)
        $ACL = $Key.GetAccessControl()
        $Rights = [System.Security.AccessControl.RegistryRights]::FullControl
        $Inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
        $Propagation = [System.Security.AccessControl.PropagationFlags]::None
        $Type = [System.Security.AccessControl.AccessControlType]::Allow
        $ACL.SetAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($Admin, $Rights, $Inheritance, $Propagation, $Type)))
        $Key.SetAccessControl($ACL)
        $Key.Close()
        $Key = $SubKey.Insert(0, 'HKLM:\')
        $ACL = Get-Acl -Path $Key
        $TrustedInstaller = [System.Security.Principal.NTAccount]'NT SERVICE\TrustedInstaller'
        $ACL.SetOwner($TrustedInstaller)
        $ACL | Set-Acl -Path $Key
    }
    End
    {
        'SeTakeOwnershipPrivilege', 'SeRestorePrivilege' | Grant-Privilege -Disable
    }
}