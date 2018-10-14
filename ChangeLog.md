# ChangeLog #

## Build 3.1.2.0 ##

- Added a new -WindowsStore flag which will sideload the latest Microsoft Windows Store, and its dependencies, into Windows 10 Enterprise LTSC. Only an image detected as Windows 10 Enterprise LTSC will be processed.
- Added further detection of Windows 10 Enterprise LTSC when applying registry settings that affect default Provisioned Application Packages.
- Removed the recursive clean-up of the \WinSxS\Backup directory.
- Updated the SetupComplete.cmd script.
>> *This script will be getting replaced with a full PowerShell script within the next few updates*
- Updated the WIM files containing the Microsoft DaRT 10 Debugging Tools to build 17663.