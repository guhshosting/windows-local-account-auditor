# windows-local-account-auditor 1.0.0

> Release preparation update (2026-10-05): see [current executable qualification and package provenance](RELEASE-QUALIFICATION.md). Historical validation and pending-test statements in this document describe the original development snapshot. The final ZIP is assembled after qualification and has not been run on Windows.


A Windows x64 command-line utility that audits locally observable local users, groups, direct membership evidence, and machine account/password policy. C++17, CMake, MSVC, MIT licensed. No GUI, telemetry, authentication, password testing, or intentional network access. The executable only reads documented Windows APIs and writes its report to standard output/error.

## Usage

```powershell
.\windows-local-account-auditor.exe
.\windows-local-account-auditor.exe --summary
.\windows-local-account-auditor.exe --users
.\windows-local-account-auditor.exe --groups
.\windows-local-account-auditor.exe --policy
.\windows-local-account-auditor.exe --user Administrator
.\windows-local-account-auditor.exe --json
.\windows-local-account-auditor.exe --users --json
.\windows-local-account-auditor.exe --help
.\windows-local-account-auditor.exe --version
```

Choose one view, optionally with `--json`. Views select report sections; acquisition always captures the complete inventory to support findings and membership matching. `--user` matches an enumerated local name using Windows ordinal case-insensitive comparison; it never submits an arbitrary supplied name to an account API. Quote names containing spaces. Default output separates users, groups/membership evidence, machine policy, findings, and acquisition failures. Human text quotes names/descriptions and escapes control characters to prevent terminal control injection. Console output is UTF-16 through WriteConsoleW; redirected output is UTF-8 without BOM. JSON errors go to stderr, with no success document on fatal/argument/not-found errors.

## Scope and safety

All NetAPI server parameters are literal `nullptr`; there is no remote-machine argument. Before account acquisition, NetServerGetInfo(101) rejects domain controllers and refuses to proceed if role detection fails. Normal local user accounts are enumerated with FILTER_NORMAL_ACCOUNT. Trust/computer accounts, Active Directory, nested membership expansion, effective rights, and tokens are outside scope.

Members are acquired at level 0 as SIDs only. Matching against the acquired local inventory requires no name lookup. The only LookupAccountSidW calls accept SIDs built from the fixed BUILTIN alias list (`S-1-5-32-544/545/546/547/551/555/580`), to obtain localized built-in group names. No observed member SID or arbitrary account/group name reaches that resolver. Those identifiers belong to the Windows BUILTIN namespace and do not name domain identities. A missing mapping remains unavailable. Custom group SIDs remain unavailable because NetLocalGroupEnum exposes names rather than SIDs and this implementation does not perform arbitrary identity resolution.

The application never creates, deletes, enables, disables or modifies accounts; never changes passwords, memberships, policy, rights, registry, ACLs; never logs on, validates a password or impersonates; never opens LSASS, reads SAM files, hashes, LSA secrets or DPAPI secrets. USER_INFO_4 is used for metadata only; its password member is never read (NetUserGetInfo documents it as NULL). No sockets, WinHTTP, WinINet, LDAP, DC discovery or remote enumeration are used. Windows implements local management calls internally; packet-level network silence has not been measured. No such measurement is claimed.

## Privileges and privacy

Run with existing privileges first. Access depends on local security policy. The program neither elevates nor enables privileges. Denied operations produce explicit inaccessible fields and source/error evidence. An administrator may obtain more information; an empty acquired set during a failure is never proof that no accounts/groups exist. Data is a non-atomic snapshot and accounts may change during enumeration.

Names, SIDs, comments and membership evidence are security-relevant. Protect redirected reports accordingly. No report is automatically saved, uploaded, or sent elsewhere. No credentials, password material, unrelated environment variables, token dump, or secrets are collected. Validation artifacts may contain this test host's account information; they are excluded from the release ZIP.

## Interpretation

Machine policy comes from NetUserModalsGet(0/3). It is reported separately from each user's flags/state. It may reflect centrally configured policy as currently exposed locally; the utility does not determine policy provenance, password complexity, or whether any actual password meets a rule.

Administrator/Guest identification uses the final RID of a SID obtained directly for a local user (500/501), so renaming/localization does not change identification. DefaultAccount/WDAGUtilityAccount use RIDs 503/504. Group identification uses BUILTIN SIDs, not assumed English names. Administrators, Backup Operators, Power Users, Remote Desktop Users and Remote Management Users receive a broad privileged/access-sensitive classification; Users and Guests receive false. Other groups receive unknown, not a claim of lack of privilege.

Findings describe observations rather than compromise, malicious behavior, vulnerability, or password strength. An enabled direct Administrators member is evidence of group configuration, not proof of effective administrative access: token creation, UAC filtering, deny rights, logon type and nested membership are not evaluated. A disabled member remains configuration evidence. Password-not-required does not establish a blank password. Old/unknown last logon does not establish abandonment. Counts are exposed metadata, not an event history. `user_may_change_password` reports the inverse exposed UF_PASSWD_CANT_CHANGE flag, not an effective ACL evaluation.

See [JSON and time semantics](docs/json.md), [schema](docs/schema.json), [acquisition API reference](docs/acquisition.md), and [validation](docs/validation.md).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Acquisition APIs completed; intentional limitations and unknown fields may remain |
| 1 | Fatal failure, unsupported DC, role detection failure, Unicode/output failure |
| 2 | Partial acquisition or inaccessible source; a usable report is normally emitted |
| 3 | Invalid command-line arguments |
| 4 | Requested local user absent from a successfully acquired inventory |

Findings do not affect exit code. If inventory acquisition is partial, a requested missing user returns 2 rather than asserting absence. Known design limitations (custom group SIDs, unresolved identities, zero last-logon metadata) are represented in field statuses/findings and do not independently cause exit 2.

## Build and support

Supported target platforms: Windows 10, Windows 11, and supported Windows Server releases with local accounts (x64). Domain controllers are deliberately unsupported. Actually validated platform: Windows Server 2025 Standard Evaluation, build 26100. Windows 10/11 and other Server releases have not been physically qualified.

Install CMake >=3.20 and Visual Studio C++ Build Tools with a Windows SDK. In an x64 developer shell:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cmake -S . -B build-analyze -A x64 -DENABLE_ANALYZE=ON
cmake --build build-analyze --config Release
```

MSVC builds use /W4 /WX /permissive- /sdl, static CRT, control-flow guard, DEP and ASLR. The included tool scripts use this validation host's Visual Studio/LLVM/Cppcheck paths; adapt those paths for another installation without weakening the checks. The release requires no separate Visual C++ redistributable. The executable is unsigned.
