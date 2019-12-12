Function Import-Win32API
{
    [CmdletBinding(DefaultParameterSetName = 'Load')]
    Param
    (
        [Parameter(ParameterSetName = 'Load')]
        [Switch]$Load,
        [Parameter(ParameterSetName = 'Unload')]
        [Switch]$Unload
    )

    $Win32APIParams = @{ Namespace = 'Win32API'; PassThru = $true }
    Switch ($PSCmdlet.ParameterSetName)
    {
        'Load'
        {
            $Win32APIParams.MemberDefinition = '[DllImport("advapi32.dll", SetLastError = true)] public static extern Int32 RegLoadKey(Int32 hKey, String lpSubKey, String lpFile);'
            $Win32APIParams.Name = 'Win32RegLoad'
            Break
        }
        'Unload'
        {
            $Win32APIParams.MemberDefinition = '[DllImport("advapi32.dll", SetLastError = true)] public static extern Int32 RegUnLoadKey(Int32 hKey, String lpSubKey);'
            $Win32APIParams.Name = 'Win32RegUnLoad'
            Break
        }
    }
    Add-Type @Win32APIParams
}