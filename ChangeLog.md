# ChangeLog #

## Build 3.1.2.7 ##

- Updated the Debugging Tools for Windows 10 to version 17763.107
- There is a new "Whitelist" value that can be used with the -MetroApps parameter. In the Resources directory there is an AppxPackageWhitelist.xml file where one can add Provisioned Appx Packages by their DisplayName.  The removal process will then remove all Provisioned Appx Packages that are NOT whitelisted. This is convenient for those who do not want to remove all Appx Packages nor want to constantly select the same Appx Packages each time they optimize an image.
- The Win32Calc has been updated with its Feature Package CAB file(s) version 17763.1
- Registry values have been updated and some new ones added.
- A handful of processes have been changed around and include additional Try/Catch blocks for error-handling.
- Made multiple code changes to processes, variables and methods for handling the WIM file.