# ChangeLog #

## Build 3.2.5.3 (06-04-2019) ##

- Added a Set-Privacy.ps1 script in the 'Resources/Additional/Setup' folder that can be run when the new image is in a live state. You can automatically execute it by running the Set-Privacy.bat and it will output its results to Set-Privacy.txt. Tasks and services to be disabled can be modified by adding or removing a task or service name from the appropriate arrays at the start of the script.
- If the -ISO switch is used to create new bootable installation media and the Windows ADK is not installed, or the ADK root path is unable to be queried in the registry, a Windows Form dialog will display allowing the end-user to manually select the oscdimg.exe premastering tool from any location.
- Additional registry entries have been added to disable handwriting and linguistic telemetry.
- Activity History, Storage Sense and the Modern UI Swap File are now disabled by default. Disabling Storage Sense removes the potential of device activity from unknowingly being accessed, syncronized or published without explicit permission. Disabling Storage Sense prevents the automatic removal of objects without explicit permission. The disabling of the Modern UI Swap File frees up an additional 256MB of disk space. This swap file is ONLY used by Modern UI Apps and has no effect on the real system swap file - pagefile.sys
- Updated the certificate fingerprint signature with my Certificate Authority's latest CodeSigning Certificate.