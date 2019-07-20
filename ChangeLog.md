# ChangeLog #

## Build 3.2.6.0 (07-20-2019) ##

- The directory structure of Optimize-Offline has been changed.
- All helper functions used by Optimize-Offline are now in a separate script in the 'Lib' folder.
- Multiple processes have been updated.
- Optimize-Offline can now integrate personal registry template (.reg) files added to the 'Content\Additional\Registry' folder when the -Additional switch is used. No editing of these template files is required and Optimize-Offline will copy and edit them accordingly to apply them to the appropriate offline image's registry hives. An 'Additional Tweaks.reg' template file is included.
- If the Microsoft.Windows.FileExplorer (c5e2524a-ea46-4f67-841f-6a9465d9d515) System Application is removed, the Start Menu clean-up process will be adjusted as to not include the UWP File Explorer.
- Windows Store bundle packages have been updated.
- Additional code changes and improvements.