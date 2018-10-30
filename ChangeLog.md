# ChangeLog #

## Build 3.1.2.4 ##

- The -Build parameter has been removed. This was originally added to verify an image being optimized was supported; however, it is no longer required since the script automatically queries the build number from the image itself.
- In order support additional languages, all language cabinet (.cab) file packages for the integration of Microsoft Edge 10.17763.1 into Windows 10 LTSC 2019 have been uploaded to the \Resources\MicrosoftEdge directory.
- The script now automatically gets the default language of the Windows 10 LTSC 2019 image being optimized and applies the Microsoft Edge 10.17763.1 cabinet file packages of the same language.
- How the verbose content is displayed has been tweaked and cleaned-up a bit, and now outputs to the console window with a single-space instead of a double-space.