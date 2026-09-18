[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = "Stop"
$script = Join-Path $PSScriptRoot "publish.py"
& python $script @Arguments
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
