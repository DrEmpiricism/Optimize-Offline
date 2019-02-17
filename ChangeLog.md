# ChangeLog #

## Build 3.1.3.8 (02-17-2019) ##

- Extremely minor updates and changes to the offline registry hives' settings and values.
- Updated the Windows Store Appx Package Bundles.
- Corrected a log mispelling and context.

**Updated on 02-17-2019**

- On builds RS5+ (17663+) Microsoft updated its ClipBoard history service allowing for cross-device access, which consequently rendered it vulnerable to unintended malware injection. In this very small update, I have added the appropriate registry entries that disables ClipBoard history and its service.