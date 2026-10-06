# Acquisition sources

> Release preparation update (2026-10-05): see [current executable qualification and package provenance](../RELEASE-QUALIFICATION.md). Historical validation and pending-test statements in this document describe the original development snapshot. The final ZIP is assembled after qualification and has not been run on Windows.


| Purpose | Documented API / level | Locality |
|---|---|---|
| Refuse DCs / establish role | NetServerGetInfo 101 | nullptr server, no discovery |
| Normal local user names | NetUserEnum 0, FILTER_NORMAL_ACCOUNT | nullptr server; paged |
| Account metadata / SID | NetUserGetInfo 4 | nullptr server; name only from enumeration |
| Local group names / comments | NetLocalGroupEnum 1 | nullptr server; paged |
| Raw member SIDs | NetLocalGroupGetMembers 0 | nullptr server; group only from enumeration |
| Password policy | NetUserModalsGet 0 | nullptr server |
| Lockout policy | NetUserModalsGet 3 | nullptr server |
| Localized BUILTIN names | LookupAccountSidW | nullptr server, fixed BUILTIN alias SIDs only |
| SID validation/formatting | IsValidSid, GetSidSubAuthorityCount, GetSidSubAuthority, ConvertSidToStringSidW | memory-only |

NetAPI buffers have RAII NetApiBufferFree ownership; converted SID buffers have LocalFree ownership. Failures retain source, subject and numeric error. Enumeration pages preserve acquired entries on later failure. Detailed user acquisition may fail without losing the enumerated name. A group-member failure preserves prior pages and marks membership incomplete. Account flags are interpreted as exposed by USER_INFO_4, with no authorization testing.

References: [NetUserGetInfo](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusergetinfo), [USER_INFO_4](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_4), [NetLocalGroupGetMembers](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupgetmembers), [NetUserModalsGet](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsget), [LookupAccountSid](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountsidw). LookupAccountSid is not used for arbitrary or external SIDs: its general resolution behavior would exceed this tool's scope. Reading domain/remote identities, even when present in local membership, is intentionally avoided.
