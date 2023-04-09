Function Get-PathSize {
  Param
  (
    [Parameter(Mandatory = $true)]
    [String]$Path
  )
  $size = 0
  Get-ChildItem $Path -Recurse -File | ForEach-Object {
    $size += $_.Length
  }
  return $size
}