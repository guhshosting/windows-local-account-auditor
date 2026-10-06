param([switch]$VerifyExisting)
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root
$release=Join-Path $root 'release'
$zip=Join-Path $release 'windows-local-account-auditor-v1.0.0-windows-x64.zip'
$sidecar="$zip.sha256"
if(-not $VerifyExisting) {
 New-Item -ItemType Directory -Force $release | Out-Null
 $stage=Join-Path $root ('artifacts\package-stage-'+[guid]::NewGuid().ToString('N'))
 New-Item -ItemType Directory -Force $stage | Out-Null
 Copy-Item -LiteralPath 'build\Release\windows-local-account-auditor.exe' -Destination $stage
 Copy-Item -LiteralPath README.md,LICENSE -Destination $stage
 Copy-Item -LiteralPath docs -Destination $stage -Recurse
 Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force -CompressionLevel Optimal
 $hash=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
 "$hash  $([IO.Path]::GetFileName($zip))" | Set-Content -LiteralPath $sidecar -Encoding ascii
}
$expected=(Get-Content -LiteralPath $sidecar).Split(' ')[0]
$actual=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
if($actual -ne $expected){throw 'Release checksum mismatch'}
$extract=Join-Path $root ('artifacts\zip-smoke-'+[guid]::NewGuid().ToString('N'))
Expand-Archive -LiteralPath $zip -DestinationPath $extract
$exe=Join-Path $extract 'windows-local-account-auditor.exe'
$allowed=@('windows-local-account-auditor.exe','README.md','LICENSE','docs\acquisition.md','docs\json.md','docs\schema.json','docs\validation.md')
$files=@(Get-ChildItem -LiteralPath $extract -File -Recurse | ForEach-Object {$_.FullName.Substring($extract.Length+1)} | Sort-Object)
if(Compare-Object ($allowed | Sort-Object) $files){throw 'Release file manifest mismatch'}
if((Get-FileHash -LiteralPath $exe).Hash -ne (Get-FileHash -LiteralPath 'build\Release\windows-local-account-auditor.exe').Hash){throw 'Extracted executable differs from verified build'}
$version=& $exe --version
if($LASTEXITCODE -ne 0 -or $version -ne 'windows-local-account-auditor 1.0.0'){throw 'Extracted version smoke failed'}
$help=& $exe --help
if($LASTEXITCODE -ne 0 -or -not (($help -join "`n").Contains('Usage:'))){throw 'Extracted help smoke failed'}
& $exe --summary | Set-Content artifacts/extracted-summary.txt
if($LASTEXITCODE -ne 0){throw 'Extracted summary smoke failed'}
& $exe | Set-Content artifacts/extracted-default.txt
if($LASTEXITCODE -ne 0){throw 'Extracted default smoke failed'}
& $exe --json | Set-Content artifacts/extracted.json -Encoding utf8NoBOM
if($LASTEXITCODE -ne 0){throw 'Extracted JSON smoke failed'}
if(-not (Test-Json -Json (Get-Content artifacts/extracted.json -Raw) -SchemaFile (Join-Path $extract 'docs\schema.json'))){throw 'Extracted schema failed'}
& (Join-Path $root 'scripts\validate.ps1') -Exe $exe
if($LASTEXITCODE -ne 0){throw 'Extracted CLI/live verification failed'}
$resource=(Get-Item -LiteralPath $exe).VersionInfo
if($resource.FileVersion -ne '1.0.0' -or $resource.ProductVersion -ne '1.0.0'){throw 'Version resource mismatch'}
Write-Output 'PASS: exact ZIP manifest, SHA-256, extraction, executable-byte identity, version resource, default/help/version/summary/JSON and full extracted CLI validation.'
Write-Output "ZIP: $zip"
Write-Output "SHA256: $actual"
Write-Output "Extraction: $extract"
