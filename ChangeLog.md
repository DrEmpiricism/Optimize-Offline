# ChangeLog #

## Build 3.1.1.5 ##

- The Hardened parameter value for the Registry has been temporarily removed. As such, many Hardened values have been migrated over to the default values.
- A similar Registry parameter set will be introduced next update once it's determined all new values are fully compatible.
- The -Registry parameter is now a switch again.
- Additional registry values have been added increasing telemetry blocking and non-explicit location sensor access.
- The script now backs up the offline registry hives before applying any optimized values, compresses it into a .zip file and adds it to the final save folder.
- The OS architecture is checked before the script initializes to verify a 64-bit system.
- A new helper function has been added that will automatically detect a current mounted WIM file, dismount it and clean up its directories.
- This new helper function was added in case an issue arrises where the script is accidently canceled, wherein re-running the script will automatically call the function to clean-up the previous mounted image.
- A few context menu items have been removed in order to reduce context menu clutter.
- After DaRT has been applied, the Boot and Recovery WIM files are cleaned-up prior to dismounting.
- DaRT tools applied to Windows Setup and Windows Recovery have been updated.
- Added additional SecHealthUI (Windows Defender) Group Policy/Registry values to be auto-disabled if it's detected SecHealthUI as a System Application has been removed.
- When an ISO is supplied as the source image, its file structure now gets optimized and rebuild before the script's finalization process.
- Tweaked the OneDrive removal process.
- Optimized the C# code used to adjust process privileges for registry ownership granting.
- Added a few additional Try/Catch blocks to monitor errors that may occur during the script's initialzation process.
>> As a side note, a secondary PowerShell script will be getting introduced soon that will replace the SetupComplete.cmd and offer setup security that is end-user controllable.