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
        Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public class AccessToken
{
    [DllImport ("advapi32.dll", SetLastError = true)] static extern Boolean LookupPrivilegeValue (String Host, String Name, ref Int64 Luid);
    [DllImport ("advapi32.dll", ExactSpelling = true, SetLastError = true)] static extern Boolean AdjustTokenPrivileges (IntPtr TokenHandle, Boolean RevokeAllPrivileges, ref TOKEN_PRIVILEGES NewTokenState, Int32 BufferLength, IntPtr PreviousTokenState, IntPtr ReturnLength);
    [DllImport ("advapi32.dll", ExactSpelling = true, SetLastError = true)] static extern Boolean OpenProcessToken (IntPtr ProcessToken, Int32 DesiredAccess, ref IntPtr hObject);
    [DllImport ("kernel32.dll", SetLastError = true)] static extern Boolean CloseHandle (IntPtr hObject);

    [StructLayout (LayoutKind.Sequential, Pack = 1)] struct TOKEN_PRIVILEGES { public Int32 PrivilegeCount; public Int64 Luid; public Int32 Attributes; }

    internal const Int32 SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const Int32 SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const Int32 TOKEN_QUERY = 0x00000008;
    internal const Int32 TOKEN_ADJUST_PRIVILEGES = 0x00000020;

    public static void AdjustPrivilege (IntPtr ProcessToken, String Privilege, Boolean Enable)
    {
        var TokenHandle = IntPtr.Zero;
        if (!OpenProcessToken (ProcessToken, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref TokenHandle)) { throw new Win32Exception (); }
        try
        {
            var Privileges = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = 0, Attributes = Enable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_DISABLED, };
            if (!LookupPrivilegeValue (null, Privilege, ref Privileges.Luid) || !AdjustTokenPrivileges (TokenHandle, false, ref Privileges, 0, IntPtr.Zero, IntPtr.Zero)) { throw new Win32Exception (); }
        }
        finally { CloseHandle (TokenHandle); }
    }
}
'@
        $CurrentProcess = Get-Process -Id $PID
    }
    Process
    {
        $Privilege | ForEach-Object -Process { [AccessToken]::AdjustPrivilege($CurrentProcess.Handle, $PSItem, !$Disable.IsPresent) }
    }
    End
    {
        $CurrentProcess.Close()
    }
}