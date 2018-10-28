# ChangeLog #

## Build 3.1.2.2 ##

- Added a new -MicrosoftEdge switch which will integrate Microsoft Edge Browser 10.0.17763.1 into Windows 10 Enterprise LTSC 2019. Only an image detected as Windows 10 Enterprise LTSC 2019 will be processed.
- Re-added the -Features switch which will output a Gridview list of all enabled Windows Features for selective disabling.
- Removed the -OneDrive switch and the removal of OneDrive as a process. This switch and process were just script clutter.
- Updated and added multiple Default registry values and settings.
- Updated the SetupComplete script with additional commands and rules specific to telemetry.
- Updated a few helper functions and removed a helper function that was not necessary.