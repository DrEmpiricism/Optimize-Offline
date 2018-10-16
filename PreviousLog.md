# Previous Version Log #

## 3.1.2.0 (10-14-2018) ##

- Added a new -WindowsStore flag which will sideload the latest Microsoft Windows Store, and its dependencies, into Windows 10 Enterprise LTSC. Only an image detected as Windows 10 Enterprise LTSC will be processed.
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

## 3.1.1.7 (10-06-2018) ##

- Added a -Features switch which will populate a Gridview list of all enabled Windows Optional Features for selective disabling.
- Updated the code of a handful of helper functions.
- The build of the image for any process that requires it is now taken directly from the WIM file instead of the -Build parameter.
- Added additional registry values for telemetry, location sensors and background application access.

## 3.1.1.6 (10-04-2018) ##

- Added support for the new Windows Enterprise LTSC.
- Updated the Win32 Calculator to the latest RS5 LTSC build.
- Corrected an unassigned variable.
- Added a -NoSetup switch that will prevent the setup and post-installation script (SetupComplete.cmd) from being applied to the image.
- Updated some SecHealthUI registry properties.
- Fixed an inproperly formatted console message.

## 3.1.1.5 (10-02-2018) ##

- The Hardened parameter value for the Registry has been temporarily removed. As such, many Hardened values have been migrated over to the default values.
- A similar Registry parameter set will be introduced next update once it's determined all new values are fully compatible.
- The -Registry parameter is now a switch again.
- Additional registry values have been added increasing telemetry blocking and non-explicit location sensor access.
- The script now backs up the offline registry hives before applying any optimized values, compresses it into a .zip file and adds it to the final save folder.
- The OS architecture is checked before the script initializes to verify a 64-bit system.
- A new helper function has been added that will automatically detect a current mounted WIM file, dismount it and clean up its directories.
- This new helper function was added in case an issue arrises where the script is accidently canceled, wherein re-running the script will automatically call the function to clean-up the previous mounted image.
- A few context menu items have been removed in order to reduce context menu clutter.
- After DaRT has been applied, the Boot and Recovery WIM files are cleaned-up prior to dismounting.
- DaRT tools applied to Windows Setup and Windows Recovery have been updated.
- Added additional SecHealthUI (Windows Defender) Group Policy/Registry values to be auto-disabled if it's detected SecHealthUI as a System Application has been removed.
- When an ISO is supplied as the source image, its file structure now gets optimized and rebuild before the script's finalization process.
- Tweaked the OneDrive removal process.
- Optimized the C# code used to adjust process privileges for registry ownership granting.
- Added a few additional Try/Catch blocks to monitor errors that may occur during the script's initialzation process.

**Displays the previous 5 version updates of Optimize-Offline.**