If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    [IO.DirectoryInfo]$ProfilePath = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | ForEach-Object -Process { $PSItem.GetValue('ProfileImagePath') } | Where-Object { $PSItem -like "*defaultuser0*" }
    If ($ProfilePath.Exists)
    {
        Clear-Host
        Write-Host "Removing the DefaultUser0 profile." -ForegroundColor Yellow
        Get-CimInstance -Class Win32_UserProfile | Where-Object { ($PSItem.LocalPath | Split-Path -Leaf) -eq 'defaultuser0' } | Remove-CimInstance
        $ProfilePath.Refresh()
        If ($ProfilePath.Exists -and (Test-Path -Path $ProfilePath.FullName))
        {
            Invoke-Expression -Command ('TAKEOWN /F "{0}"' -f $ProfilePath.FullName) > $null
            Invoke-Expression -Command ('ICACLS "{0}" /GRANT *S-1-1-0:F' -f $ProfilePath.FullName) > $null
            Invoke-Expression -Command ('CMD RMDIR /S /Q "{0}"' -f $ProfilePath.FullName) > $null
        }
    }
    Else { Exit }
}