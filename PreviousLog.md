# Previous Version Log #

## Build 3.1.2.7 (11-10-2018) ##

- Updated the Debugging Tools for Windows 10 to version 17763.107
- There is a new "Whitelist" value that can be used with the -MetroApps parameter. In the Resources directory there is an AppxPackageWhitelist.xml file where one can add Provisioned Appx Packages by their DisplayName.  The removal process will then remove all Provisioned Appx Packages that are NOT whitelisted. This is convenient for those who do not want to remove all Appx Packages nor want to constantly select the same Appx Packages each time they optimize an image.
- The Win32Calc has been updated with its Feature Package CAB file(s) version 17763.1
- Registry values have been updated and some new ones added.
- A handful of processes have been changed around and include additional Try/Catch blocks for error-handling.
- Made multiple code changes to processes, variables and methods for handling the WIM file.

## Build 3.1.2.6 (11-04-2018) ##

- Some helper function and process code have been changed and updated.
- Updated and added some additional registry settings.
- Tweaked the logfile header and footer.

## Build 3.1.2.5 (10-31-2018) ##

- COM component objects that are created in a process are now released from memory when the process completes.
- Updated a few registry optimization values applied with the -Registry "Default" parameter.
- Removed redundant and unnecessary code within the process that applies Microsoft DaRT 10.

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

**Displays the previous 5 version updates of Optimize-Offline.**