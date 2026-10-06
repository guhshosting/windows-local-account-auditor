param([string]$Exe = '.\build\Release\windows-local-account-auditor.exe')
$ErrorActionPreference='Stop'
function Assert-True($condition,$message) {if(-not $condition){throw $message}}
$schema=(Resolve-Path '.\docs\schema.json').Path
$raw = (& $Exe --json | Out-String)
$code=$LASTEXITCODE
Assert-True ($code -eq 0) "Live acquisition returned $code"
Assert-True (Test-Json -Json $raw -SchemaFile $schema) 'Live JSON schema failed'
$raw | Set-Content artifacts/live.json -Encoding utf8NoBOM
$r=$raw | ConvertFrom-Json
Assert-True ($r.acquisition.domain_controller.value -eq $false) 'DC guard metadata'
Assert-True ($r.users.Count -gt 0) 'No live users'
Assert-True ($r.groups.Count -gt 0) 'No live groups'
$localUsers=@(Get-LocalUser)
$localGroups=@(Get-LocalGroup)
Assert-True ($localUsers.Count -eq $r.users.Count) 'Independent user count mismatch'
Assert-True ($localGroups.Count -eq $r.groups.Count) 'Independent group count mismatch'
foreach($u in $r.users) {
 $local=@($localUsers | Where-Object Name -CEQ $u.name)
 Assert-True ($local.Count -eq 1) 'Independent local name mismatch'
 Assert-True ($local[0].SID.Value -eq $u.fields.sid.value) 'Independent SID mismatch'
 Assert-True ($local[0].Enabled -eq $u.fields.enabled.value) 'Independent enabled state mismatch'
 Assert-True ($u.fields.enabled.value -is [bool]) 'Enabled must be boolean'
 Assert-True ($u.fields.flags.value -is [long] -or $u.fields.flags.value -is [int]) 'Flags must be integer'
}
foreach($g in $r.groups) {
 $local=@($localGroups | Where-Object Name -CEQ $g.name)
 Assert-True ($local.Count -eq 1) 'Independent group name mismatch'
 if($g.fields.sid.status -eq 'available'){Assert-True ($local[0].SID.Value -eq $g.fields.sid.value) 'Builtin group SID mismatch'}
}
foreach($view in @('--summary','--users','--groups','--policy')) {
 $json=(& $Exe $view --json | Out-String)
 Assert-True ($LASTEXITCODE -eq 0) "View $view exit"
 Assert-True (Test-Json -Json $json -SchemaFile $schema) "View $view schema"
 $human=(& $Exe $view | Out-String)
 Assert-True ($LASTEXITCODE -eq 0 -and $human.Contains('windows-local-account-auditor')) "Human view $view"
}
$selected=(& $Exe --user $r.users[0].name --json | Out-String)
Assert-True ($LASTEXITCODE -eq 0) 'User lookup exit'
Assert-True (Test-Json -Json $selected -SchemaFile $schema) 'User lookup schema'
Assert-True (($selected | ConvertFrom-Json).users.Count -eq 1) 'User lookup count'
$missing=& $Exe --user '__wlaa_absent_fixture_6ef8d5__' 2>&1
Assert-True ($LASTEXITCODE -eq 4) 'Missing user must return 4'
$invalid=& $Exe --invalid 2>&1
Assert-True ($LASTEXITCODE -eq 3) 'Invalid argument must return 3'
$missingArg=& $Exe --user 2>&1
Assert-True ($LASTEXITCODE -eq 3) 'Missing argument must return 3'
$conflict=& $Exe --users --groups 2>&1
Assert-True ($LASTEXITCODE -eq 3) 'Conflicting view must return 3'
$version=& $Exe --version
Assert-True ($LASTEXITCODE -eq 0 -and $version -eq 'windows-local-account-auditor 1.0.0') 'Version mismatch'
$help=& $Exe --help
Assert-True ($LASTEXITCODE -eq 0 -and ($help -join "`n").Contains('Usage:')) 'Help mismatch'
$fixture=(& '.\build\Release\audit_tests.exe' --emit-json | Out-String)
Assert-True ($LASTEXITCODE -eq 0) 'Fixture emission failed'
Assert-True (Test-Json -Json $fixture -SchemaFile $schema) 'Fixture schema failed'
$fixture | Set-Content artifacts/fixture.json -Encoding utf8NoBOM
$broken=$raw.Replace('"schema_version":"1.0.0"','"schema_version":"9.0.0"')
Assert-True (-not (Test-Json -Json $broken -SchemaFile $schema -ErrorAction SilentlyContinue)) 'Schema must reject wrong version'
$fixtureObject=$fixture | ConvertFrom-Json
$fixtureObject.users[0].fields.enabled.status='unknown'
$fixtureObject.users[0].fields.enabled.value=$false
Assert-True (-not (Test-Json -Json ($fixtureObject | ConvertTo-Json -Depth 100) -SchemaFile $schema -ErrorAction SilentlyContinue)) 'Schema must reject unknown with false value'
Write-Output "PASS: live Server 2025 JSON schema, all views and CLI exit codes; independently matched $($r.users.Count) users and $($r.groups.Count) groups using Get-LocalUser/Get-LocalGroup; fixture Unicode JSON schema; negative schema cases."
