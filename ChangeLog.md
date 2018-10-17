# ChangeLog #

## Build 3.1.2.1 ##

- Converted the -Registry switch into a parameter that will accept set values of "Default" and "Harden" for applying registry hive settings and values.
- Running -Registry "Harden" will apply the Default entries, as well as additional entries that are more restritive of system sensor and background access as well as more stringint telemetry blocking.
>> More settings will be added to the "Harden" parameter set in the next update.
- Removed the recursive deletion of the WinSxS OneDrive directories during OneDrive's removal as I've had people concerned about /ScanHealth returning benign corruption results due to these missing directories.
- All log files and any package lists are now archived into a single zip file.
- The default language of the image is assigned to a variable and used in place of the static 'en-US' string in order to accommodate other image languages.