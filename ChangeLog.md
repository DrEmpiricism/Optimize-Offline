# ChangeLog #

## Build 3.1.1.2 ##

- When an ISO is supplied as the source image, its entire media structure is extracted instead of just the install.wim and boot.wim (more details on this below).
- The elapsed optimization time is returned at the end of the script to detail exactly how long the full optimization processes took.
- More scheduled tasks have been included in the SetupComplete.cmd script, as well as the inclusion of new firewall rules and the automatic removal of CompatTelRunner.
>> CompatTelRunner is an automatic running spy/telemetry Windows process that often results in high CPU and disk usage.
>> CompatTelRunner can be particularly tricky to remove when the system is online because Windows, by default, prevents the process from being killed.
- If an ISO is supplied as the source image, the -NetFx3 parameter can be used with the boolean variable "$true" instead of a full path to the NetFx3 payload files.
- An OfflineServicing answer file is applied to the image that increases the bootup and loading of the OS by removing or reducing superfluous Microsoft startup verbosity.
- A PowerShell process "Take Ownership" context menu item has been added.
- The image clean-up process has been improved.