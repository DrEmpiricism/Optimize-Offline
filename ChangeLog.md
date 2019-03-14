# ChangeLog #

## Build 3.2.4.2 (03-13-2019) ##

- Fixed an issue with mounting an image where DISM would return errors that the mount path was inaccessible or already being used.
- Fixed an issue where the rebuilding and exporting of the optimized image would export all indexes instead of the one optimized.
- Fixed an issue where Optimize-Offline would create an empty directory for additional content. It now only creates required folders if the appropriate content is located in the 'Additional' directory folder(s).
- Updated the Microsoft DaRT 10 Microsoft Windows 10 Debugging Tools.
