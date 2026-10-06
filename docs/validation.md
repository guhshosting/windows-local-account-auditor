# Validation and qualification record

> Release preparation update (2026-10-05): see [current executable qualification and package provenance](../RELEASE-QUALIFICATION.md). Historical validation and pending-test statements in this document describe the original development snapshot. The final ZIP is assembled after qualification and has not been run on Windows.


Validation date: 2026-10-03. Host: Windows Server 2025 Standard Evaluation, x64, build 26100. Toolchain: MSVC 19.51.36260 (Visual Studio 18 Build Tools), CMake 4.4.3, LLVM clang-tidy 23.1.2, Cppcheck 2.22.0. Only this Windows version was actually executed. No Windows 10/11 or other Server version validation is claimed.

| Check | Result |
|---|---|
| MSVC x64 Release /W4 /WX /permissive- /sdl | PASS, zero compiler warnings |
| CTest | PASS, 4/4 test cases; fixture case contains the account/state/membership/policy/Unicode/error regressions |
| MSVC /analyze with warnings as errors | PASS, zero reported project diagnostics |
| clang-tidy clang-analyzer, bugprone, performance checks, warnings as errors | PASS, zero project diagnostics; tool-default non-user/header warning filtering applies |
| Cppcheck warning/style/performance/portability, exit-on-error | PASS, zero diagnostics |
| Live read-only Server 2025 audit | PASS: 8 normal local users, 28 groups, 0 operational acquisition errors |
| Independent local inventory comparison | PASS: Get-LocalUser names/SIDs/enabled state and Get-LocalGroup names/recognized built-in SIDs match |
| Restricted sandbox-token execution | PASS: 8 users, 28 groups, 0 acquisition errors, exit 0; not a physical standard-user qualification |
| JSON Schema Draft 7 validation | PASS: complete report, all filtered views, selected-user output, deterministic Unicode fixture, negative schema cases |
| Independent Python JSON parser | PASS: UTF-8 without BOM, scalar types, ordering, Unicode/escaping and sentinel representation |
| CLI integration | PASS: help/version, all views, name lookup, invalid options/missing arguments/conflicting views, absent user (4), invalid arguments (3) |
| Fatal output handling | PASS: closed stdout pipe returns 1, with diagnostic on stderr |
| Partial acquisition | PASS in deterministic fixtures: inaccessible state stays null/unknown, existing evidence is retained, exit 2 |
| Source safety and binary imports | PASS: read-only call-path review, nullptr NetAPI servers, fixed BUILTIN-only resolver inputs, no forbidden operations/imports |
| PE inspection | PASS: x64 console subsystem, ASLR, DEP and control-flow guard |

The source safety review inspected every acquisition path and its arguments. Account-management calls are enumeration/read operations only. Name resolution accepts only fixed BUILTIN alias SIDs, never observed SIDs, names from membership or user CLI input. No credential APIs, authentication attempts, password/hash access, direct SAM/LSASS access, LSA/DPAPI secrets, remote NetAPI targets, sockets/HTTP/LDAP, impersonation or account/policy/membership/ACL/registry mutations are present. Import inspection supports that source review; it is not proof about every internal Windows service activity. Packet-level network observation was not performed.

Fixture coverage includes ordinary enabled and disabled users, built-in Administrator and Guest identities, localized Russian/French names, Unicode descriptions, administrator/direct privileged membership, nested and external-looking unresolved members, no transitive inference, never-expiring and password-not-required flags, finite/never account expiration, unknown/unavailable last logon, zero counts and unknown-count sentinel, finite/unlimited policy values, disabled and finite lockout, inaccessible and partial acquisition, native SID/RID extraction including missing/invalid SIDs, deterministic ordering, JSON escaping/status distinctions, CLI parsing and exit semantics. Role guard tests reject primary and backup domain-controller flags. No fixture changes a real user, password, group or policy.

Validation logs are kept under `artifacts/`: release-build.txt, ctest.txt, msvc-analyze.txt, clang-tidy.txt, cppcheck.txt, json-validation.txt, python-validation.txt, safety-review.txt, imports.txt and pe-headers.txt. Live/fixture reports and extraction smoke logs also reside there; security-relevant live data is excluded from release packaging.

## Release verification

`scripts/package.ps1` creates `release/windows-local-account-auditor-v1.0.0-windows-x64.zip` and a `.zip.sha256` sidecar. It verifies the sidecar, extracts the exact archive into a new directory, checks the exact seven-file manifest, compares extracted executable bytes with the validated build, checks PE version strings, runs default/help/version/summary/JSON commands, validates JSON against the schema inside the archive, and reruns all CLI/live checks against the extracted executable. `artifacts/package-validation.txt` records the completed result. Use `-VerifyExisting` to test the same ZIP again without recreating it.

The seven files are the executable, README.md, LICENSE and docs/acquisition.md, docs/json.md, docs/schema.json, docs/validation.md. Source, build directories, fixture executables and live host reports are excluded. The executable is unsigned and uses a static MSVC CRT.

## Remaining physical Windows 11 and Windows 10 qualification

Verify the published SHA-256 and run the extracted executable on physical x64 Windows 11 and Windows 10 systems before claiming qualification there. Record the exact edition/build, administrator and standard-user results, every CLI view/error code, JSON/schema parsing, and local-only inventory comparisons. Use preconfigured test systems containing renamed built-in accounts, localized groups, Unicode descriptions, disabled/ordinary accounts, expiration/lockout variations and restricted permissions. Domain-joined member-machine/external SID behavior and localized Windows installations have fixture coverage but need live qualification. Do not run acquisition on a domain controller; the refusal path should also be qualified on a dedicated DC without enumerating accounts.

Repeat read-only import/source review for any platform-specific changes. If packet-level silence is to be claimed, perform and record packet capture separately; no such claim is made by this release. Qualify other supported Server releases before listing them as tested.

## Known limitations

Only normal local user accounts are enumerated. DCs are refused; role detection can fail when the required local service/access is unavailable, causing fail-closed exit 1. Detailed acquisition is subject to access restrictions and concurrent configuration changes; the snapshot is not atomic. Custom group SIDs and identities outside the acquired inventory are intentionally unresolved. Seven significant built-in groups are recognized; other group privilege classifications remain unknown. Nested memberships, effective rights, token/UAC behavior, policy provenance/complexity, actual password contents/strength and logon event histories are not acquired. Last-logon and count metadata may be incomplete. Known scope omissions remain explicit statuses even when all acquisition APIs succeed with exit 0.
