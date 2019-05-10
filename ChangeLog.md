# ChangeLog #

## Build 3.2.4.9 (05-09-2019) ##

- You may now select the final compression type for the image which includes the solid WIM archive (ESD file).
- The -ImagePath parameter has been renamed to -SourcePath.
- The Remove-Container helper function has been updated.
- Multiple registry settings have been appended and have removed duplicate entries.
- The -NetFx3 switch - and the integration of the .NET Framework Payload packages - has been removed as a feature. This is to ensure the integrity of images that have been updated offline with the latest Monthly Cumulative Update(s).
- The -Drivers switch has been removed and driver integration has been combined with the incorporation of additional content via the -Additional switch. Likewise, the 'Drivers' folder has been moved to the '\Resources\Additional' directory. It was redundant to have a separate switch for driver integration and user-defined additional content.
- The DaRT .wim files have been updated.
- The Windows Store Application Packages have been updatred.
- Optimize-Offline now also checks for regular Windows 10 Enterprise and Windows 10 Education versions when setting system telemetry.
- The custom Start Menu Layout has been updated.
- Additional small updates and code changes.