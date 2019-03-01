# ChangeLog #

## Build 3.2.4.0 (02-27-2019) ##

- Optimize-Offline now checks if the install.wim contains more than one Windows 10 Edition (multi-index). If it does, a gridview list will output allowing for the selection of the Windows 10 Edition to optimize. Likewise, the -Index parameter has been removed and is no longer required when calling Optimize-Offline.
- The process for disabling Windows Defender SmartScreen has been updated for Windows 10 build 17763.
- Merged and optimized various processes to increase script speed.
- Fixed an issue where the IntegratedPackages.log would not display all packages integrated into the image.
- Microsoft Edge policy settings no longer get applied to Windows 10 LTSC 2019, as the LTSC GPO does not contain these settings.
- A new 'Additional' folder located in the 'Resources' directory can be used to copy setup content or an answer file to the image. If an answer file is supplied (must be named unattend.xml), it will be copied to the '\Windows\Panther' directory of the mounted image where it will automatically run during Windows 10 installation. If any setup scripts or content is supplied, it will be copied to the '\Windows\Setup\Scripts' directory of the mounted image which will run scripts (SetupComplete.cmd, OOBE.cmd, etc.) during Windows 10 setup.