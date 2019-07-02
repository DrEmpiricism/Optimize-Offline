# ChangeLog #

## Build 3.2.5.7 (07-02-2019) ##

- Updated and expanded the System Applications that are returned for removal.
- Removed some registry settings that were unecessary in the latest Windows 10 builds.
- Removed the Get-OSCDIMG helper function and integrated it directly into the ISO creation process. This quickens the oscdimg.exe selection pop-up screen and also prevents it from popping-up in the background.
- If the XBox System and Provisioned Application Packages are removed, the XBox (Gaming) Immersive Control Panel page is now also removed (like Windows Defender).
- Added a new optional online script in the 'Resources\Additional\Setup' folder called 'Remove-OneDrive' which will perform a complete proper removal of Microsoft OneDrive. It can be executed by running the 'Remove-OneDrive.bat' as an administrator (like Set-Privacy).
- Additional small code changes and enhancements.