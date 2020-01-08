Function Grant-Privilege
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        [String[]]$Privilege,
        [Switch]$Disable
    )

    Begin
    {
        Set-ErrorAction SilentlyContinue
        Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public class AccessToken
{
    [DllImport ("advapi32.dll", SetLastError = true)] static extern bool LookupPrivilegeValue (String Host, String Name, ref long luid);
    [DllImport ("advapi32.dll", ExactSpelling = true, SetLastError = true)] static extern bool AdjustTokenPrivileges (IntPtr Token, bool disall, ref TOKEN_PRIVILEGES newst, int len, IntPtr prev, IntPtr relen);
    [DllImport ("advapi32.dll", ExactSpelling = true, SetLastError = true)] static extern bool OpenProcessToken (IntPtr CurrentProcess, int acc, ref IntPtr ProcessToken);
    [DllImport ("kernel32.dll", SetLastError = true)] static extern bool CloseHandle (IntPtr Handle);

    [StructLayout (LayoutKind.Sequential, Pack = 1)] struct TOKEN_PRIVILEGES { public int Count; public long Luid; public int Attr; }

    internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

    public static void AdjustPrivilege (IntPtr CurrentProcess, String Privilege, bool enable)
    {
        var ProcessToken = IntPtr.Zero;
        if (!OpenProcessToken (CurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref ProcessToken)) { throw new Win32Exception (); }
        try
        {
            var Privileges = new TOKEN_PRIVILEGES { Count = 1, Luid = 0, Attr = enable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_DISABLED, };
            if (!LookupPrivilegeValue (null, Privilege, ref Privileges.Luid) || !AdjustTokenPrivileges (ProcessToken, false, ref Privileges, 0, IntPtr.Zero, IntPtr.Zero)) { throw new Win32Exception (); }
        }
        finally { CloseHandle (ProcessToken); }
    }
}
'@
        $CurrentProcess = Get-Process -Id $PID
    }
    Process
    {
        $Privilege | ForEach-Object -Process { [AccessToken]::AdjustPrivilege($CurrentProcess.Handle, $PSItem, !$Disable) }
    }
    End
    {
        $CurrentProcess.Close()
        Set-ErrorAction -Restore
    }
}