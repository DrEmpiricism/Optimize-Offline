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
        $Form = New-Object -TypeName System.Windows.Forms.Form
        $Form.Text = 'Compression Type'
        $Form.Width = 258
        $Form.Height = 180
        $Form.ShowIcon = $false
        $Form.TopMost = $true
        $Form.MaximizeBox = $false
        $Form.MinimizeBox = $false
        $Label = New-Object -TypeName System.Windows.Forms.Label
        $Label.Size = New-Object -TypeName System.Drawing.Size(185, 20)
        $Label.Text = 'Select Final Image Compression.'
        $Label.BackColor = 'Transparent'
        $Label.AutoSize = $false
        $Label.TextAlign = 'MiddleCenter'
        $Label.Font = 'Segoe UI, 9pt'
        $ListBox = New-Object -TypeName System.Windows.Forms.ListBox
        $ListBox.Location = New-Object -TypeName System.Drawing.Size(10, 22)
        $ListBox.Size = New-Object -TypeName System.Drawing.Size(220, 20)
        $ListBox.Height = 80
        $ListBox.Font = 'Segoe UI, 9pt'
        ForEach ($CompressionType In @('None', 'Fast', 'Maximum', 'Solid')) { [Void]$ListBox.Items.Add($CompressionType) }
        $ListBox.SelectedItem = 'Fast'
        $OKButton = New-Object -TypeName System.Windows.Forms.Button
        $OKButton.Location = New-Object -TypeName System.Drawing.Size(10, 110)
        $OKButton.Size = New-Object -TypeName System.Drawing.Size(75, 23)
        $OKButton.Text = 'OK'
        $OKButton.DialogResult = [Windows.Forms.DialogResult]::OK
        $Form.AcceptButton = $OKButton
        [Void]$Form.Controls.Add($OKButton)
        [Void]$Form.Controls.Add($Label)
        [Void]$Form.Controls.Add($ListBox)
        $Form.Add_Shown{ $Form.Activate() }
        $InputResult = $Form.ShowDialog()
        While ($InputResult -eq 'Cancel') { $InputResult = $Form.ShowDialog() }
        If ($InputResult -eq [Windows.Forms.DialogResult]::OK) { $ListBox.SelectedItem }
    }
    End
    {
        $Form.Close()
        $Form.Dispose()
    }
}