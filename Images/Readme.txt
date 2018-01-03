Default Account Pictures names, image-types and dimentions:
	guest.bmp (448x448)
	guest.png (448x448)
	user.bmp (448x448)
	user.png (448x448)
	user-192.png (192x192)
	user-48.png (48x48)
	user-40.png (40x40)
	user-32.png (32x32)

HD Default LockScreen name, image-type and dimentions:
	img100.jpg (3840x2160 96 dpi)

**The HD dimentional fields can be slightly increased based on how good of a display you have, though this will increase its load time.**

Non-HD Default LockScreen name, image-type and dimentions:
	img100.jpg (1920x1200 96 dpi)
	img100.jpg (1920x1080 96 dpi)

System logo image-type and size:
	ANY_NAME.bmp (120x120)

OEM image locations:
Default Account Pictures: "%ProgramData%\Microsoft\Default Account Pictures"
Default Lock Screen: "%WinDir%\Web\Screen"
System Logo: "%WinDir%\System32\oobe\info\logo"

Additional OEM locations:
User OEM Theme: "%LocalAppData%\Microsoft\Windows\Themes\oem.theme"
User Default Windows Theme: "%WinDir%\Resources\Themes\aero.theme"
User Default Lock Screen: "%ProgramData%\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly\LockScreen_Z"

**This script takes ownership of the default OEM images from TrustedInstaller, sets the appropriate ICACLS permissions and replaces the default image, then restores the default directory/file ownership and permissions.**

All wallpaper images, that do not include a default image replacement, are added recursively to their own directories within the main "%WinDir%\Web\Wallpaper" directory.

IMPORTANT NOTE:
- If the img100.jpg default lock screen is replaced, SFC /ScanNow will "repair" the image and replace it with the default image.
- Replacing the default images does NOT cause any system corruption; however, Windows Servicing will replace these images with the default Windows images.
- Despite this, the custom lock screen will continue to display despite being replaced, as it's also saved at "%ProgramData%\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly\LockScreen_Z" and this takes precedence over its default location unless it's manually changed.