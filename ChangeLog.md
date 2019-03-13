# ChangeLog #

## Build 3.2.4.2 (03-13-2019) ##

- Fixes an issue with mounting an image where DISM would return errors that the mount path was inaccessible or already being used.
- Fixed an issue where the rebuilding and exporting of the optimized image would export all indexes instead of the one optimized.
- Fixed an issue where Optimize-Offline would create an empty directory for additional content. It now only creates required folders if the appropriate content is located in the 'Additional' directory folder(s)

## Build 3.2.4.1 (03-13-2019) ##

- Improved and expanded the Additional directory's structure (located in '\Resources\Additional') and can now be enabled using the new -Additional switch.
- Changed the method used to rebuild and export WIM files to legacy DISM as it is significantly faster than PowerShell's DISM cmdlet.
- Expanded, modified and removed legacy code and replaced it with updated code.
- Added a check for regular Windows 10 Enterprise for various telemetry features to the already current Window 10 Enterprise LTSC 2019 checks.
- Added shorter alias' for certain switches (i.e. -Calc can be used in place of -Win32Calc; -Store can be used in place of -WindowsStore, etc.) You can view all of them in Optimize-Offline's information header.
- A custom Default Apps Association file is automatically imported - '\Resources\CustomAppAssociations.xml'
- Additional registry value and code changes.