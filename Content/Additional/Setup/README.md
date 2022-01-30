If adding additional user content, place any setup files, scripts or content to be added to the image here.

## Consider the following to assure a successful application of SetupComplete.cmd ##

Any setup content, including answer files, scripts and executables, should ALWAYS be removed immediately after they are run by the installing Administrator unless they are designed for specific tasks when a new user account is created or logs in. Not doing so can allow other users with access to the system to run this content or extract potential sensitive data. This can be automated by adding their automatic removal to the SetupComplete.cmd that is supplied by default.

Typically %WINDIR%\Setup\Scripts\SetupComplete.cmd runs with local system permissions and starts immediately after image installation reaches the desktop. However, if you're image uses "OEM activation" also referred to as "System Locked Pre-installation (SLP)" then SetupComplete.cmd is potentially blocked from running. This is by Microsoft design as stated: SetupComplete.cmd is "disabled when using OEM product keys" [Microsoft Document](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-a-custom-script-to-windows-setup?view=windows-11)

For the above reasons, post image installation best practice is to is to inspect the contents of the %WINDIR%\Setup\Scripts folder. (1) Confirm successful script application or (2) resolve discovery that SetupComplete.cmd was disabled by running %WINDIR%\Setup\Scripts\Run_TI_SetupComplete_online.cmd which applies the SetupComplete.cmd as Trusted Installer.

## Additional Script folder Content ##

The Set-Additional and Remove-OneDrive PowerShell scripts can be run by executing their associated Set-Additional.cmd and Remove-OneDrive.cmd scripts by right-clicking them and selecting 'Run as Administrator.'

The Set-Additional script is supplied to only be run by users who are familiar with disabling Windows 10 default services and scheduled tasks. If you are unfamiliar with how the Set-Additional script works, or are unsure of what services and/or scheduled tasks it disables, it is strongly recommended to NOT run the script until you understand it in its entirity. The Set-Additional script does back-up the default states of all services and scheduled tasks before it processes their disabling so any can be reverted back to its default state if required. Moreover, prior to running the Set-Additional script, thoroughly inspect both the Services.json and ScheduledTasks.json files to make sure nothing is set to be disabled that will be either be required by the running system or by the end-user.
