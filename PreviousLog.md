# Previous Version Log #

## Build 3.1.2.4 (10-30-2018) ##

- The -Build parameter has been removed. This was originally added to verify an image being optimized was supported; however, it is no longer required since the script automatically queries the build number from the image itself.
- In order support additional languages, all language cabinet (.cab) file packages for the integration of Microsoft Edge 10.17763.1 into Windows 10 LTSC 2019 have been uploaded to the \Resources\MicrosoftEdge directory.
- The script now automatically gets the default language of the Windows 10 LTSC 2019 image being optimized and applies the Microsoft Edge 10.17763.1 cabinet file packages of the same language.
- How the verbose content is displayed has been tweaked and cleaned-up a bit, and now outputs to the console window with a single-space instead of a double-space.

## Build 3.1.2.3 (10-29-2018) ##

- If an ISO file is used as the source image, and the Windows ADK is installed, the script will automatically remaster and create a new bootable Windows Installation Media ISO before it finalizes.
- This alieviates the annoyance of having to copy the fully expanded ISO media to another location in order to create a bootable ISO after the script completes.
- If any of the required boot files cannot be located by the script, it will silently skip over the ISO creation process and return the fully expanded ISO media like before.
- Fixed a sintax error within the SetupComplete.cmd script.
- Removed some redundant and unecessary variables.
- Added the SeBackupPrivilege to the File and Folder Ownership functions, as this process privilege allows for system-level recursive nagivation of protected folders and directories.

## Build 3.1.2.2 (10-28-2018) ##

- Added a new -MicrosoftEdge switch which will integrate Microsoft Edge Browser 10.0.17763.1 into Windows 10 Enterprise LTSC 2019. Only an image detected as Windows 10 Enterprise LTSC 2019 will be processed.
- Re-added the -Features switch which will output a Gridview list of all enabled Windows Features for selective disabling.
- Removed the -OneDrive switch and the removal of OneDrive as a process. This switch and process were just script clutter.
- Updated and added multiple Default registry values and settings.
- Updated the SetupComplete script with additional commands and rules specific to telemetry.
- Updated a few helper functions and removed a helper function that was not necessary.

## Build 3.1.2.1 (10-17-2018) ##

- Converted the -Registry switch into a parameter that will accept set values of "Default" and "Harden" for applying registry hive settings and values.
- Running -Registry "Harden" will apply the Default entries as well as additional entries that are more restrictive of system sensor and background access as well as more stringint telemetry blocking.
>> More settings will be added to the "Harden" parameter set in the next update.
- Removed the recursive deletion of the WinSxS OneDrive directories during OneDrive's removal as I've had people concerned about /ScanHealth returning benign corruption results due to these missing directories.
- All log files and any package lists are now archived into a single zip file.
- The default language of the image is assigned to a variable and used in place of the static 'en-US' string in order to accommodate other image languages.

## 3.1.2.0 (10-14-2018) ##

- Added a new -WindowsStore switch which will sideload the latest Microsoft Windows Store, and its dependencies, into Windows 10 Enterprise LTSC 2019. Only an image detected as Windows 10 Enterprise LTSC 2019 will be processed.
- Added further detection of Windows 10 Enterprise LTSC when applying registry settings that affect default Provisioned Application Packages.
- Removed the recursive clean-up of the \WinSxS\Backup directory.
- Updated the SetupComplete.cmd script.
>> *This script will be getting replaced with a full PowerShell script within the next few updates*
- Updated the WIM files containing the Microsoft DaRT 10 Debugging Tools to build 17663.
- Cleaned-up multiple registry values that are applied.

**Displays the previous 5 version updates of Optimize-Offline.**