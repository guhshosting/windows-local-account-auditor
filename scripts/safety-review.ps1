param([string]$Exe = '.\build\Release\windows-local-account-auditor.exe')
$ErrorActionPreference='Stop'
$forbidden='\b(?:NetUser(?:Add|Del|SetInfo|ChangePassword)|NetLocalGroup(?:Add|Del|SetInfo|AddMembers|DelMembers|SetMembers)|NetUserModalsSet|NetGetDCName|DsGetDcName\w*|LookupAccountName\w*|Lsa\w+|LogonUser\w*|CreateProcessWithLogon\w*|Impersonate\w*|ReadProcessMemory|OpenProcess|Cred\w+|CryptUnprotectData|RegSetValue\w*|SetNamedSecurityInfo\w*|SetFileSecurity\w*|WSA\w*|socket|connect|send|recv|WinHttp\w*|InternetOpen\w*|ldap_\w+|Sam\w+)\s*\('
$hits=@(Get-ChildItem src -Include *.cpp,*.h -Recurse | Select-String -Pattern $forbidden)
if($hits.Count){$hits;throw 'Forbidden API detected'}
$source=Get-Content src/windows.cpp -Raw
$source=[regex]::Replace($source,'"(?:\\.|[^"\\])*"','""')
foreach($api in @('NetUserEnum','NetUserGetInfo','NetLocalGroupEnum','NetLocalGroupGetMembers','NetUserModalsGet','NetServerGetInfo')) {
 $calls=[regex]::Matches($source,"\b$api\s*\(([^,]+),")
 if($calls.Count -eq 0){throw "Expected local API missing: $api"}
 foreach($call in $calls){if($call.Groups[1].Value.Trim() -ne 'nullptr'){throw "Nonlocal server parameter: $api"}}
}
$lookup=[regex]::Matches($source,'LookupAccountSidW\s*\(([^,]+),([^,]+),')
foreach($call in $lookup){if($call.Groups[1].Value.Trim() -ne 'nullptr' -or $call.Groups[2].Value.Trim() -ne 'raw'){throw 'Unexpected SID resolver input'}}
if($lookup.Count -ne 2){throw 'Builtin resolver call graph changed; review required'}
Write-Output 'PASS: source forbidden-API review; all NetAPI server arguments nullptr; name resolution confined to fixed BUILTIN SIDs. Manual call-path review also required.'
$dumpbin='C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\dumpbin.exe'
$imports=& $dumpbin /imports $Exe
if($LASTEXITCODE -ne 0){throw 'Import inspection failed'}
$imports | Set-Content artifacts/imports.txt
if(($imports -join "`n") -match '(?i)WS2_32\.dll|WINHTTP\.dll|WININET\.dll|WLDAP32\.dll|LogonUser|NetUserSetInfo|LsaRetrievePrivateData|ReadProcessMemory'){throw 'Unexpected import'}
$headers=& $dumpbin /headers $Exe
$headers | Set-Content artifacts/pe-headers.txt
if($LASTEXITCODE -ne 0){throw 'PE inspection failed'}
foreach($required in @('8664 machine','Dynamic base','NX compatible','Control Flow Guard')){if(-not (($headers -join "`n").Contains($required))){throw "Missing x64/hardening flag: $required"}}
Write-Output 'PASS: x64 binary imports and ASLR/DEP/CFG; no socket/HTTP/LDAP, authentication, mutation or credential imports detected. This is not packet capture.'


