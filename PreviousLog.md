# Previous Version Log #

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

## 3.1.1.9 (10-12-2018) ##

- Added the removal of Windows Defender loggers if SecHealthUI is a removed System Application.
- Added the removal of telemetry loggers to the optimizied registry value settings.
- Improved the syntax within the SetupComplet.cmd script.
- Corrected an incorrect comparison operator for the final image clean-up process.

## 3.1.1.8 (10-11-2018) ##

- Updated the Win32 Calculator.
- Included the disabling of Security Health Services' SmartScreen integration if SecHealthUI is a removed System Application.
- Added and updated multiple registry values.
- Updated the SetupComplete.cmd script.
- Included more support for Windows 10 Enterprise LTSC.
- Fixed the logging timestamp so it now outputs the proper script completion time.

**Displays the previous 5 version updates of Optimize-Offline.**