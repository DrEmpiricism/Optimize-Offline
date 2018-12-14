# ChangeLog #

## Build 3.1.3.0 (updated on 12-14-2019) ##

- Made multiple changes and removals to registry settings applied, as many of them have changed and are not applicable to older builds. As such, Optimize-Offline no longer supports builds lower than RS4 (17134).
- The -Registry parameter has been changed to a switch.
- Many registry settings that modified the layout of the desktop and GUI have been removed as to allow for pure end-user customization.
- Removed multiple Helper Functions that are no longer applicable to the new registry changes.
- There is no longer a SetupComplete.cmd script that is generated and added to the image allowing for its inclusion using a distribution share (i.e. OEM folder added to the installation media).
- The -NoISO switch has been removed.
- There is a new -ISO switch that can be used to remaster a new ISO if an ISO was used at the source image.
- Updated the Windows Store Appx Packages.
- Additional optimization process and code changes.