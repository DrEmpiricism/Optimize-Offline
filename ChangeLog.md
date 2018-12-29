# ChangeLog #

## Build 3.1.3.4 (updated on 12-29-2019) ##

- Removed the registry setting that prevented Windows Update from searching for default system drivers. Enabling this setting offline can prevent the online system from detecting multiple OEM drivers during Windows Setup.
- The old -NetFx3 and -Drivers parameters have been converted to switches and no longer require the paths to the integration packages. Instead, drivers to integrate into the image can be added to the Resources > Drivers folder in Optimize-Offline's root directory. Likewise, the .NET Framework 3 payload packages are now present in the Resources > NetFx3 folder.