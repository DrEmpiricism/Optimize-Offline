Function Get-CompressionType
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        [Void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
        [Void][Reflection.Assembly]::LoadWithPartialName('System.Drawing')
    }
    Process
    {
        $Form = New-Object -TypeName Windows.Forms.Form -ErrorAction:$ErrorActionPreference
        $Form.Text = 'Compression Type'
        $Form.Width = 258
        $Form.Height = 180
        $Form.ShowIcon = $false
        $Form.TopMost = $true
        $Form.MaximizeBox = $false
        $Form.MinimizeBox = $false
        $Label = New-Object -TypeName Windows.Forms.Label -ErrorAction:$ErrorActionPreference
        $Label.Size = New-Object -TypeName Drawing.Size(185, 20) -ErrorAction:$ErrorActionPreference
        $Label.Text = 'Select Final Image Compression.'
        If ($PSVersionTable.PSVersion.Major -ge 6) { $Label.BackColor = [Drawing.Color]::Transparent; $Label.Font = [Drawing.Font]::New('Segoe UI', 9) }
        Else { $Label.BackColor = 'Transparent'; $Label.Font = 'Segoe UI, 9pt' }
        $Label.AutoSize = $false
        $Label.TextAlign = 'MiddleCenter'
        $ListBox = New-Object -TypeName Windows.Forms.ListBox -ErrorAction:$ErrorActionPreference
        $ListBox.Location = New-Object -TypeName Drawing.Size(10, 22) -ErrorAction:$ErrorActionPreference
        $ListBox.Size = New-Object -TypeName Drawing.Size(220, 20) -ErrorAction:$ErrorActionPreference
        $ListBox.Height = 80
        If ($PSVersionTable.PSVersion.Major -ge 6) { $ListBox.Font = [Drawing.Font]::New('Segoe UI', 9) }
        Else { $ListBox.Font = 'Segoe UI, 9pt' }
        ForEach ($CompressionType In @('None', 'Fast', 'Maximum', 'Solid')) { [Void]$ListBox.Items.Add($CompressionType) }
        $ListBox.SelectedItem = 'Fast'
        $OKButton = New-Object -TypeName Windows.Forms.Button -ErrorAction:$ErrorActionPreference
        $OKButton.Location = New-Object -TypeName Drawing.Size(10, 110) -ErrorAction:$ErrorActionPreference
        $OKButton.Size = New-Object -TypeName Drawing.Size(75, 23) -ErrorAction:$ErrorActionPreference
        $OKButton.Text = 'OK'
        $OKButton.DialogResult = [Windows.Forms.DialogResult]::OK
        $Form.AcceptButton = $OKButton
        [Void]$Form.Controls.Add($OKButton)
        [Void]$Form.Controls.Add($Label)
        [Void]$Form.Controls.Add($ListBox)
        $Form.Add_Shown{ $Form.Activate() }
        $InputResult = $Form.ShowDialog()
        If ($InputResult -eq [Windows.Forms.DialogResult]::OK) { $InputResult = $ListBox.SelectedItem }
        Else { $InputResult = 'Fast' }
        $InputResult
        <#
        While ($InputResult -eq [Windows.Forms.DialogResult]::Cancel) { $InputResult = $Form.ShowDialog() }
        If ($InputResult -eq [Windows.Forms.DialogResult]::OK) { $ListBox.SelectedItem }
        #>
    }
    End
    {
        $Form.Close()
        $Form.Dispose()
    }
}