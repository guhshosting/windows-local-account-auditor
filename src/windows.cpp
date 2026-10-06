#include "core.h"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <lm.h>
#include <memory>
#include <sddl.h>
#include <stdexcept>
namespace audit {
namespace {
struct NetBuffer {
    LPBYTE data = nullptr;
    ~NetBuffer() {
        if (data)
            NetApiBufferFree(data);
    }
    NetBuffer() = default;
    NetBuffer(const NetBuffer &) = delete;
    NetBuffer &operator=(const NetBuffer &) = delete;
};
std::string text(LPCWSTR s) { return s ? utf8(s) : std::string{}; }
std::string sid_text(PSID sid) {
    if (!sid || !IsValidSid(sid))
        return {};
    LPWSTR out = nullptr;
    if (!ConvertSidToStringSidW(sid, &out))
        return {};
    const std::unique_ptr<wchar_t, decltype(&LocalFree)> owner(out, LocalFree);
    return utf8(out);
}
std::string status(DWORD code) { return code == ERROR_ACCESS_DENIED ? "inaccessible" : "unavailable"; }
void issue(Report &r, const char *api, const std::string &subject, DWORD code) {
    r.issues.push_back({api, subject, status(code), code});
}
Fields user_fields() {
    Fields f;
    for (const auto *key :
         {"sid", "rid", "built_in", "enabled", "password_required", "password_never_expires",
          "user_may_change_password", "account_expires", "password_age_seconds", "last_logon",
          "bad_password_count", "logon_count", "description", "flags", "password_expired", "locked_out"})
        f[key] = Value{};
    return f;
}
void users(Report &r) {
    DWORD resume = 0;
    for (;;) {
        NetBuffer b;
        DWORD count = 0, total = 0;
        const DWORD previous = resume;
        const auto rc =
            NetUserEnum(nullptr, 0, FILTER_NORMAL_ACCOUNT, &b.data, 64 * 1024, &count, &total, &resume);
        if (rc != NERR_Success && rc != ERROR_MORE_DATA) {
            issue(r, "NetUserEnum", "users", rc);
            return;
        }
        if (count && !b.data)
            throw std::runtime_error("NetUserEnum returned invalid buffer");
        const auto *rows = reinterpret_cast<const USER_INFO_0 *>(b.data);
        for (DWORD i = 0; i < count; ++i) {
            if (!rows[i].usri0_name)
                throw std::runtime_error("NetUserEnum returned missing name");
            User u;
            u.name = text(rows[i].usri0_name);
            u.fields = user_fields();
            NetBuffer detail;
            const auto detail_rc = NetUserGetInfo(nullptr, rows[i].usri0_name, 4, &detail.data);
            if (detail_rc != NERR_Success) {
                for (auto &f : u.fields)
                    f.second = Value::state(status(detail_rc));
                issue(r, "NetUserGetInfo(4)", u.name, detail_rc);
            } else {
                if (!detail.data)
                    throw std::runtime_error("NetUserGetInfo returned invalid buffer");
                const auto *p = reinterpret_cast<const USER_INFO_4 *>(detail.data);
                const auto flags = p->usri4_flags;
                for (const auto &field : decode_account_flags(flags))
                    u.fields[field.first] = field.second;
                const auto sid = sid_text(p->usri4_user_sid);
                if (sid.empty())
                    issue(r, "USER_INFO_4 SID", u.name, ERROR_INVALID_SID);
                else {
                    u.fields["sid"] = Value::text(sid);
                    u.fields["rid"] = rid_from_sid(p->usri4_user_sid);
                    if (u.fields["rid"].status == "available") {
                        const auto rid = std::stoul(u.fields["rid"].value);
                        u.fields["built_in"] = Value::text(rid == 500   ? "Administrator"
                                                           : rid == 501 ? "Guest"
                                                           : rid == 503 ? "DefaultAccount"
                                                           : rid == 504 ? "WDAGUtilityAccount"
                                                                        : "ordinary");
                    }
                }
                u.fields["password_expired"] = Value::boolean(p->usri4_password_expired != 0);
                u.fields["account_expires"] = timestamp(p->usri4_acct_expires, true);
                u.fields["password_age_seconds"] = counter(p->usri4_password_age);
                u.fields["last_logon"] = timestamp(p->usri4_last_logon, false);
                u.fields["bad_password_count"] = counter(p->usri4_bad_pw_count);
                u.fields["logon_count"] = counter(p->usri4_num_logons);
                u.fields["description"] =
                    p->usri4_comment ? Value::text(text(p->usri4_comment)) : Value::state("absent");
            }
            r.users.push_back(std::move(u));
        }
        if (rc == NERR_Success)
            return;
        if (resume == previous) {
            issue(r, "NetUserEnum pagination", "users", ERROR_INVALID_DATA);
            return;
        }
    }
}
// Lookup is confined to compile-time BUILTIN alias SIDs, never observed/external SIDs.
// Arbitrary member SIDs are matched to our enumerated local inventory only.
struct Builtin {
    DWORD rid = 0;
    const char *label = "";
    bool privileged = false;
};
const std::array<Builtin, 7> builtins = {{{544, "Administrators", true},
                                          {545, "Users", false},
                                          {546, "Guests", false},
                                          {555, "Remote Desktop Users", true},
                                          {551, "Backup Operators", true},
                                          {547, "Power Users", true},
                                          {580, "Remote Management Users", true}}};
struct BuiltinName {
    std::wstring name;
    std::string sid, label;
    bool privileged = false;
};
std::vector<BuiltinName> builtin_names(Report &r) {
    std::vector<BuiltinName> names;
    for (const auto &b : builtins) {
        const std::wstring sid_string = L"S-1-5-32-" + std::to_wstring(b.rid);
        PSID raw = nullptr;
        if (!ConvertStringSidToSidW(sid_string.c_str(), &raw))
            throw std::runtime_error("Builtin SID construction failed");
        const std::unique_ptr<void, decltype(&LocalFree)> owner(raw, LocalFree);
        DWORD n = 0, d = 0;
        SID_NAME_USE use = SidTypeUnknown;
        LookupAccountSidW(nullptr, raw, nullptr, &n, nullptr, &d, &use);
        const auto error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) {
            if (error != ERROR_NONE_MAPPED)
                issue(r, "BUILTIN alias name", utf8(sid_string), error);
            continue;
        }
        if (n == 0 || n > 32768 || d > 32768) {
            issue(r, "BUILTIN alias name", utf8(sid_string), ERROR_INVALID_DATA);
            continue;
        }
        std::vector<wchar_t> name(n), domain(std::max<DWORD>(d, 1));
        if (!LookupAccountSidW(nullptr, raw, name.data(), &n, domain.data(), &d, &use)) {
            issue(r, "BUILTIN alias name", utf8(sid_string), GetLastError());
            continue;
        }
        if (use != SidTypeAlias) {
            issue(r, "BUILTIN alias type", utf8(sid_string), ERROR_INVALID_DATA);
            continue;
        }
        names.push_back({name.data(), utf8(sid_string), b.label, b.privileged});
    }
    return names;
}
void members(Report &r, Group &g, LPCWSTR name) {
    DWORD_PTR resume = 0;
    for (;;) {
        NetBuffer b;
        DWORD count = 0, total = 0;
        const auto previous = resume;
        const auto rc =
            NetLocalGroupGetMembers(nullptr, name, 0, &b.data, 64 * 1024, &count, &total, &resume);
        if (rc != NERR_Success && rc != ERROR_MORE_DATA) {
            g.fields["membership_status"] = Value::state(status(rc));
            issue(r, "NetLocalGroupGetMembers(0)", g.name, rc);
            return;
        }
        if (count && !b.data)
            throw std::runtime_error("NetLocalGroupGetMembers returned invalid buffer");
        const auto *p = reinterpret_cast<const LOCALGROUP_MEMBERS_INFO_0 *>(b.data);
        for (DWORD i = 0; i < count; ++i) {
            const auto sid = sid_text(p[i].lgrmi0_sid);
            if (sid.empty())
                issue(r, "Group member SID", g.name, ERROR_INVALID_SID);
            g.members.push_back({sid, Value::state("unavailable"), "unresolved"});
        }
        if (rc == NERR_Success) {
            g.fields["membership_status"] = Value::text("complete");
            return;
        }
        if (resume == previous) {
            g.fields["membership_status"] = Value::state("unavailable");
            issue(r, "Group member pagination", g.name, ERROR_INVALID_DATA);
            return;
        }
    }
}
void groups(Report &r) {
    const auto known = builtin_names(r);
    DWORD_PTR resume = 0;
    for (;;) {
        NetBuffer b;
        DWORD count = 0, total = 0;
        const auto previous = resume;
        const auto rc = NetLocalGroupEnum(nullptr, 1, &b.data, 64 * 1024, &count, &total, &resume);
        if (rc != NERR_Success && rc != ERROR_MORE_DATA) {
            issue(r, "NetLocalGroupEnum(1)", "groups", rc);
            return;
        }
        if (count && !b.data)
            throw std::runtime_error("NetLocalGroupEnum returned invalid buffer");
        const auto *p = reinterpret_cast<const LOCALGROUP_INFO_1 *>(b.data);
        for (DWORD i = 0; i < count; ++i) {
            if (!p[i].lgrpi1_name)
                throw std::runtime_error("Group name missing");
            Group g;
            g.name = text(p[i].lgrpi1_name);
            g.fields["sid"] = Value::state("unavailable");
            g.fields["recognized_builtin"] = Value::state("unknown");
            g.fields["privileged_classification"] = Value::state("unknown");
            g.fields["description"] =
                p[i].lgrpi1_comment ? Value::text(text(p[i].lgrpi1_comment)) : Value::state("absent");
            const auto k = std::find_if(known.begin(), known.end(), [&p, i](const BuiltinName &builtin) {
                return CompareStringOrdinal(p[i].lgrpi1_name, -1, builtin.name.c_str(), -1, TRUE) ==
                       CSTR_EQUAL;
            });
            if (k != known.end()) {
                g.fields["sid"] = Value::text(k->sid);
                g.fields["recognized_builtin"] = Value::text(k->label);
                g.privileged = k->privileged;
                g.fields["privileged_classification"] = Value::boolean(k->privileged);
            }
            // Custom group SIDs are intentionally unavailable: NetLocalGroupEnum exposes names only.
            members(r, g, p[i].lgrpi1_name);
            r.groups.push_back(std::move(g));
        }
        if (rc == NERR_Success)
            return;
        if (resume == previous) {
            issue(r, "NetLocalGroupEnum pagination", "groups", ERROR_INVALID_DATA);
            return;
        }
    }
}
void policy(Report &r) {
    for (const auto *k : {"minimum_password_length", "maximum_password_age_seconds",
                          "minimum_password_age_seconds", "password_history_length", "lockout_threshold",
                          "lockout_duration_seconds", "lockout_observation_window_seconds"})
        r.policy[k] = Value{};
    NetBuffer b;
    auto rc = NetUserModalsGet(nullptr, 0, &b.data);
    if (rc != NERR_Success) {
        issue(r, "NetUserModalsGet(0)", "machine policy", rc);
        for (const auto *k : {"minimum_password_length", "maximum_password_age_seconds",
                              "minimum_password_age_seconds", "password_history_length"})
            r.policy[k] = Value::state(status(rc));
    } else {
        if (!b.data)
            throw std::runtime_error("Policy buffer missing");
        const auto *p = reinterpret_cast<const USER_MODALS_INFO_0 *>(b.data);
        r.policy["minimum_password_length"] = Value::number(p->usrmod0_min_passwd_len);
        r.policy["maximum_password_age_seconds"] = duration(p->usrmod0_max_passwd_age);
        r.policy["minimum_password_age_seconds"] = duration(p->usrmod0_min_passwd_age);
        r.policy["password_history_length"] = Value::number(p->usrmod0_password_hist_len);
    }
    NetBuffer lock;
    rc = NetUserModalsGet(nullptr, 3, &lock.data);
    if (rc != NERR_Success) {
        issue(r, "NetUserModalsGet(3)", "machine policy", rc);
        for (const auto *k :
             {"lockout_threshold", "lockout_duration_seconds", "lockout_observation_window_seconds"})
            r.policy[k] = Value::state(status(rc));
    } else {
        if (!lock.data)
            throw std::runtime_error("Lockout buffer missing");
        const auto *p = reinterpret_cast<const USER_MODALS_INFO_3 *>(lock.data);
        r.policy["lockout_threshold"] = Value::number(p->usrmod3_lockout_threshold);
        if (p->usrmod3_lockout_threshold == 0) {
            r.policy["lockout_duration_seconds"] = Value::state("not_applicable");
            r.policy["lockout_observation_window_seconds"] = Value::state("not_applicable");
        } else {
            r.policy["lockout_duration_seconds"] = duration(p->usrmod3_lockout_duration);
            r.policy["lockout_observation_window_seconds"] = duration(p->usrmod3_lockout_observation_window);
        }
    }
}
class WindowsSource final : public Source {
  public:
    Report acquire() override {
        Report r;
        r.metadata["application_version"] = Value::text("1.0.0");
        r.metadata["scope"] = Value::text("local_machine");
        r.metadata["read_only"] = Value::boolean(true);
        FILETIME ft{};
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER t{};
        t.LowPart = ft.dwLowDateTime;
        t.HighPart = ft.dwHighDateTime;
        r.metadata["collected_at_unix_seconds"] =
            Value::number((t.QuadPart - 116444736000000000ULL) / 10000000ULL);
        // A domain controller has no ordinary local SAM user store. Fail closed before enumerating.
        NetBuffer server;
        const auto rc = NetServerGetInfo(nullptr, 101, &server.data);
        if (rc != NERR_Success || !server.data)
            throw std::runtime_error(
                "Cannot establish local machine role; acquisition refused (NetServerGetInfo " +
                std::to_string(rc) + ")");
        const auto *p = reinterpret_cast<const SERVER_INFO_101 *>(server.data);
        if (!local_role_allowed(p->sv101_type))
            throw std::runtime_error("Domain controllers are unsupported; domain enumeration refused");
        r.metadata["domain_controller"] = Value::boolean(false);
        users(r);
        groups(r);
        policy(r);
        analyze(r);
        return r;
    }
};
} // namespace
Report acquire_windows() {
    WindowsSource source;
    return source.acquire();
}
} // namespace audit
