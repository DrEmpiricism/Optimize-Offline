If adding additional user content, place an unattend.xml to be imported into the image here.

Because this unattend.xml answer file gets applied directly to the image, and is copied to the %WINDIR%\Panther directory, it will act indentically to an autounattend.xml answer file placed on the installation media with the exception of the WindowsPE configuration pass. Any WindowsPE configuration pass parameters must be placed in an autounattend.xml in order to set up disk partitions and layouts.
