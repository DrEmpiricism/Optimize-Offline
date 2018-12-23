# ChangeLog #

## Build 3.1.3.1 (updated on 12-23-2019) ##

- Replaced the LayoutModification.xml with a simpler version that does not include a Taskbar layout and only includes links to the Control Panel and Windows Explorer. Moreover, Optimize-Offline no longer creates the custom UWP Explorer and UEFI Firmware Reboot icons as both can be easily added in a live environment.
- Removed the disabling of the Windows Insider Program in the registry settings.
- Added the prevention of automatic device driver downloads through Windows Update.
- Enabled strong .NET Framework cryptography in the registry settings.
- Updated the "Take Ownership" context menu feature code.
- Added a Distribution Share resource directory. This directory acts just like a distribution share added to Windows installation media except that it applies all contents offline as opposed to during the Windows 10 installation process. The end-user must use the typical distribution share file structure hierarchy when adding files and/or folders to be implemented into the offline image. One can add their own custom setup scripts (SetupComplete.cmd, OOBE.cmd, etc.), custom wallpapers and logos, an unattend.xml answer file, etc. Be aware that any custom images, logos, lockscreens or themes added must also be added to an autounattend.xml or unattend.xml in order for the system to recognize and apply them at boot-up. More info on distribution shares can be found [here](https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/wsim/distribution-shares-and-configuration-sets-overview)
- Multiple registry settings have been updated and a few have been removed for example the Insider's Program is no longer disabled and is again fully functional, etc.
- Improved some Helper Functions' process procedures, error recording and handling.
- The default Hosts file is backed-up and then replaced with the latest Steven Black master hosts file.  These are generally updated once a week on GitHub.  You can read about his Host files in detail [here](https://github.com/StevenBlack/hosts)
- The ISO creation process has been updated.
- Windows Store packages have been updated.
- The Win32Calc packages have been updated.