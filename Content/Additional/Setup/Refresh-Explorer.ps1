<#
	.SYNOPSIS
		Adds a method to refresh Windows objects without having to restart the Explorer process.

	.DESCRIPTION
		This method uses a Win32 API to notify the system of any events that affect the shell and then flushes the system event buffer.
		This method uses a Win32 API to post a message that simulates an F5 keyboard input.
		This method does not issue an Explorer process restart because the system event buffer is flushed in the running environment using the Win32 API.
		This method also refreshes system objects, like changed or modified registry keys, that normally require a system reboot.
		This method is useful for quickly refreshing the desktop, taskbar, icons, wallpaper, files, environmental variables and/or visual environment.
#>

@"
Add-Type @'
using System;
using System.Runtime.InteropServices;

namespace Win32API
{
    public class Explorer
    {
        private static readonly IntPtr HWND_BROADCAST = new IntPtr (0xffff);
        private static readonly IntPtr HWND_KEYBOARD = new IntPtr (65535);
        private static readonly UIntPtr WM_USER = new UIntPtr (41504);
        private const Int32 WM_SETTINGCHANGE = 0x1a;
        private const Int32 SMTO_ABORTIFHUNG = 0x0002;
        private const Int32 VK_F5 = 273;

        [DllImport ("shell32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern Int32 SHChangeNotify (Int32 eventId, Int32 flags, IntPtr item1, IntPtr item2);
        [DllImport ("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern IntPtr SendMessageTimeout (IntPtr hWnd, Int32 Msg, IntPtr wParam, String lParam, Int32 fuFlags, Int32 uTimeout, IntPtr lpdwResult);
        [DllImport ("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        static extern bool SendNotifyMessage (IntPtr hWnd, UInt32 Msg, IntPtr wParam, String lParam);
        [DllImport ("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern Int32 PostMessage (IntPtr hWnd, UInt32 Msg, UIntPtr wParam, IntPtr lParam);

        public static void RefreshEnvironment ()
        {
            SHChangeNotify (0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero);
            SendMessageTimeout (HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "Environment", SMTO_ABORTIFHUNG, 100, IntPtr.Zero);
            SendNotifyMessage (HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "TraySettings");
        }

        public static void RefreshShell ()
        {
            PostMessage (HWND_KEYBOARD, VK_F5, WM_USER, IntPtr.Zero);
        }
    }
}
'@
[Win32API.Explorer]::RefreshEnvironment()
[Win32API.Explorer]::RefreshShell()
"@ | Out-File -FilePath "$Env:SystemRoot\Refresh-Explorer.ps1" -Encoding UTF8 -Force

If (Test-Path -Path "$Env:SystemRoot\Refresh-Explorer.ps1")
{
	New-Item -Path 'HKLM:\SOFTWARE\Classes\DesktopBackground\shell\Refresh Explorer' -ItemType Directory -Force
	New-Item -Path 'HKLM:\SOFTWARE\Classes\DesktopBackground\shell\Refresh Explorer\command' -ItemType Directory -Force
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\DesktopBackground\shell\Refresh Explorer' -Name 'Icon' -Value 'Explorer.exe' -PropertyType String -Force
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\DesktopBackground\shell\Refresh Explorer' -Name 'Position' -Value 'Bottom' -PropertyType String -Force
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\DesktopBackground\shell\Refresh Explorer\command' -Name '(default)' -Value "PowerShell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$Env:SystemRoot\Refresh-Explorer.ps1`"" -PropertyType String -Force
}