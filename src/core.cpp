#include "core.h"
#include <Windows.h>
#include <algorithm>
#include <iomanip>
#include <lm.h>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <utility>
namespace audit {
Value Value::text(std::string v) { return {"available", std::move(v), false}; }
Value Value::number(std::uint64_t v) { return {"available", std::to_string(v), true}; }
Value Value::boolean(bool v) { return {"available", v ? "true" : "false", true}; }
Value Value::state(std::string s) { return {std::move(s), "", false}; }
std::string utf8(const std::wstring &v) {
    if (v.empty())
        return {};
    if (v.size() > static_cast<size_t>(INT_MAX))
        throw std::runtime_error("Text too large");
    const auto size = static_cast<int>(v.size());
    const int n =
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, v.data(), size, nullptr, 0, nullptr, nullptr);
    if (n == 0)
        throw std::runtime_error("Invalid Unicode from acquisition");
    std::string out(static_cast<size_t>(n), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, v.data(), size, out.data(), n, nullptr, nullptr) !=
        n)
        throw std::runtime_error("Unicode conversion failed");
    return out;
}
std::string quote(const std::string &v) {
    std::ostringstream s;
    s << '"';
    for (const unsigned char c : v) {
        switch (c) {
        case '"':
            s << "\\\"";
            break;
        case '\\':
            s << "\\\\";
            break;
        case '\b':
            s << "\\b";
            break;
        case '\f':
            s << "\\f";
            break;
        case '\n':
            s << "\\n";
            break;
        case '\r':
            s << "\\r";
            break;
        case '\t':
            s << "\\t";
            break;
        default:
            if (c < 32)
                s << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(c)
                  << std::dec;
            else
                s << static_cast<char>(c);
        }
    }
    s << '"';
    return s.str();
}
Value timestamp(std::uint32_t v, bool expiration) {
    if (v == 0xFFFFFFFFu)
        return Value::state(expiration ? "never" : "unknown");
    if (v == 0 && !expiration)
        return Value::state("unknown");
    return Value::number(v);
}
Value duration(std::uint32_t v) { return v == 0xFFFFFFFFu ? Value::state("unlimited") : Value::number(v); }
Value counter(std::uint32_t v) { return v == 0xFFFFFFFFu ? Value::state("unknown") : Value::number(v); }
Value rid_from_sid(void *sid) {
    if (!sid || !IsValidSid(sid))
        return Value::state("unavailable");
    const auto count = *GetSidSubAuthorityCount(sid);
    if (count == 0)
        return Value::state("not_applicable");
    return Value::number(*GetSidSubAuthority(sid, static_cast<DWORD>(count - 1)));
}
Fields decode_account_flags(std::uint32_t flags) {
    return {{"enabled", Value::boolean((flags & UF_ACCOUNTDISABLE) == 0)},
            {"password_required", Value::boolean((flags & UF_PASSWD_NOTREQD) == 0)},
            {"password_never_expires", Value::boolean((flags & UF_DONT_EXPIRE_PASSWD) != 0)},
            {"user_may_change_password", Value::boolean((flags & UF_PASSWD_CANT_CHANGE) == 0)},
            {"locked_out", Value::boolean((flags & UF_LOCKOUT) != 0)},
            {"flags", Value::number(flags)}};
}
bool local_role_allowed(std::uint32_t server_type) {
    return (server_type & static_cast<DWORD>(SV_TYPE_DOMAIN_CTRL | SV_TYPE_DOMAIN_BAKCTRL)) == 0;
}
static bool is(const Fields &f, const char *key, const std::string &v) {
    const auto i = f.find(key);
    return i != f.end() && i->second.status == "available" && i->second.value == v;
}
void analyze(Report &r) {
    r.findings.clear();
    r.metadata["user_count"] = Value::number(r.users.size());
    r.metadata["group_count"] = Value::number(r.groups.size());
    r.metadata["acquisition_error_count"] = Value::number(r.issues.size());
    bool memberships_complete = true;
    for (const auto &i : r.issues)
        if (i.source.find("Group") != std::string::npos || i.source.find("group") != std::string::npos ||
            i.source.find("alias") != std::string::npos)
            memberships_complete = false;
    for (auto &u : r.users) {
        u.groups.clear();
        u.fields["membership_status"] =
            u.fields.count("sid") && u.fields.at("sid").status == "available"
                ? Value::text(memberships_complete ? "complete_direct_evidence" : "partial_direct_evidence")
                : Value::state("unavailable");
    }
    for (auto &g : r.groups) {
        for (auto &m : g.members) {
            m.kind = "unresolved";
            m.name = Value::state("unavailable");
            const auto matched = std::find_if(r.users.begin(), r.users.end(), [&m](const User &user) {
                return !m.sid.empty() && is(user.fields, "sid", m.sid);
            });
            if (matched != r.users.end()) {
                auto &u = *matched;
                m.kind = "local_user";
                m.name = Value::text(u.name);
                u.groups.push_back(g.name);
                if (g.privileged)
                    r.findings.push_back(
                        {is(u.fields, "enabled", "true")    ? "enabled_privileged_member"
                         : is(u.fields, "enabled", "false") ? "disabled_privileged_member"
                                                            : "privileged_member_state_unknown",
                         u.name,
                         "Direct SID membership in " + g.name +
                             ". Token, UAC, rights and nested memberships are not evaluated."});
            }
            if (m.kind == "unresolved") {
                const auto local = std::find_if(r.groups.begin(), r.groups.end(), [&m](const Group &group) {
                    return !m.sid.empty() && is(group.fields, "sid", m.sid);
                });
                if (local != r.groups.end()) {
                    m.kind = "local_group";
                    m.name = Value::text(local->name);
                }
                if (m.kind == "unresolved")
                    r.findings.push_back(
                        {"unresolved_member", g.name,
                         m.sid + ": identity resolution unavailable; no domain lookup attempted."});
            }
        }
        std::sort(g.members.begin(), g.members.end(),
                  [](const Member &a, const Member &b) { return a.sid < b.sid; });
    }
    size_t admins = 0;
    for (auto &u : r.users) {
        std::sort(u.groups.begin(), u.groups.end());
        u.groups.erase(std::unique(u.groups.begin(), u.groups.end()), u.groups.end());
        if (is(u.fields, "password_never_expires", "true"))
            r.findings.push_back({"password_never_expires", u.name, "UF_DONT_EXPIRE_PASSWD is set."});
        if (is(u.fields, "password_required", "false"))
            r.findings.push_back(
                {"password_not_required", u.name,
                 "UF_PASSWD_NOTREQD is set; this does not establish that the password is blank."});
        if (is(u.fields, "built_in", "Guest") && is(u.fields, "enabled", "true"))
            r.findings.push_back({"guest_enabled", u.name, "Local SID RID 501 and enabled account flag."});
        if (u.fields.at("account_expires").status == "available")
            r.findings.push_back(
                {"expiration_configured", u.name, "Account expiration is configured; see Unix timestamp."});
        bool admin = false;
        for (const auto &g : r.groups)
            if (is(g.fields, "sid", "S-1-5-32-544") &&
                std::find(u.groups.begin(), u.groups.end(), g.name) != u.groups.end())
                admin = true;
        if (admin && is(u.fields, "enabled", "true"))
            ++admins;
    }
    if (admins > 1)
        r.findings.push_back({"multiple_enabled_administrators", "machine",
                              std::to_string(admins) + " enabled local users have direct Administrators "
                                                       "membership; effective access is not determined."});
    if (is(r.policy, "lockout_threshold", "0"))
        r.findings.push_back(
            {"lockout_disabled", "machine", "The exposed machine lockout threshold is zero."});
    for (const auto &i : r.issues)
        r.findings.push_back({"incomplete_information", i.subject,
                              i.source + ": " + i.status + " (" + std::to_string(i.code) + ")"});
    std::sort(r.users.begin(), r.users.end(), [](const User &a, const User &b) { return a.name < b.name; });
    std::sort(r.groups.begin(), r.groups.end(),
              [](const Group &a, const Group &b) { return a.name < b.name; });
    std::sort(r.issues.begin(), r.issues.end(), [](const Issue &a, const Issue &b) {
        return std::tie(a.source, a.subject, a.code) < std::tie(b.source, b.subject, b.code);
    });
    std::sort(r.findings.begin(), r.findings.end(), [](const Finding &a, const Finding &b) {
        return std::tie(a.code, a.subject, a.evidence) < std::tie(b.code, b.subject, b.evidence);
    });
}
static std::string value_json(const Value &v) {
    return "{\"status\":" + quote(v.status) +
           ",\"value\":" + (v.status == "available" ? (v.numeric ? v.value : quote(v.value)) : "null") + "}";
}
static std::string fields_json(const Fields &f) {
    std::string s = "{";
    bool first = true;
    for (const auto &p : f) {
        if (!first)
            s += ',';
        first = false;
        s += quote(p.first) + ":" + value_json(p.second);
    }
    return s + "}";
}
static bool show(const Options &o, const char *section) {
    return o.view == "all" || o.view == section || (o.view == "user" && std::string(section) == "users");
}
std::string json(const Report &r, const Options &o) {
    std::string s = "{\"schema_version\":\"1.0.0\",\"acquisition\":" + fields_json(r.metadata) +
                    ",\"view\":" + quote(o.view) + ",\"users\":[";
    bool first = true;
    if (show(o, "users"))
        for (const auto &u : r.users) {
            if (!first)
                s += ',';
            first = false;
            s +=
                "{\"name\":" + quote(u.name) + ",\"fields\":" + fields_json(u.fields) + ",\"local_groups\":[";
            bool fg = true;
            for (const auto &g : u.groups) {
                if (!fg)
                    s += ',';
                fg = false;
                s += quote(g);
            }
            s += "]}";
        }
    s += "],\"groups\":[";
    first = true;
    if (show(o, "groups"))
        for (const auto &g : r.groups) {
            if (!first)
                s += ',';
            first = false;
            s += "{\"name\":" + quote(g.name) + ",\"fields\":" + fields_json(g.fields) + ",\"privileged\":" +
                 value_json(g.fields.count("privileged_classification")
                                ? g.fields.at("privileged_classification")
                                : Value::state("unknown")) +
                 ",\"members\":[";
            bool fm = true;
            for (const auto &m : g.members) {
                if (!fm)
                    s += ',';
                fm = false;
                s += "{\"sid\":" + quote(m.sid) + ",\"name\":" + value_json(m.name) +
                     ",\"kind\":" + quote(m.kind) + "}";
            }
            s += "]}";
        }
    s += "],\"machine_policy\":" + fields_json(show(o, "policy") ? r.policy : Fields{}) + ",\"findings\":[";
    first = true;
    for (const auto &f : r.findings) {
        if (!first)
            s += ',';
        first = false;
        s += "{\"code\":" + quote(f.code) + ",\"subject\":" + quote(f.subject) +
             ",\"evidence\":" + quote(f.evidence) + "}";
    }
    s += "],\"unavailable_information\":[";
    first = true;
    for (const auto &i : r.issues) {
        if (!first)
            s += ',';
        first = false;
        s += "{\"source\":" + quote(i.source) + ",\"subject\":" + quote(i.subject) +
             ",\"status\":" + quote(i.status) + ",\"win32_code\":" + std::to_string(i.code) + "}";
    }
    return s + "],\"warnings\":[\"Direct group membership does not establish effective access. No nested "
               "expansion or domain identity resolution. Custom group SIDs are intentionally unavailable. "
               "Last-logon metadata may be incomplete.\"]}\n";
}
static void human_fields(std::ostringstream &s, const Fields &f) {
    for (const auto &p : f)
        s << "  " << p.first << ": "
          << (p.second.status == "available" ? (p.second.numeric ? p.second.value : quote(p.second.value))
                                             : p.second.status)
          << '\n';
}
std::string human(const Report &r, const Options &o) {
    std::ostringstream s;
    s << "windows-local-account-auditor 1.0.0\nLocal, read-only account configuration evidence\n";
    s << "Summary: " << r.users.size() << " users, " << r.groups.size() << " groups, " << r.issues.size()
      << " operational acquisition errors\n";
    if (show(o, "users")) {
        s << "\nUser accounts\n";
        for (const auto &u : r.users) {
            s << quote(u.name) << '\n';
            human_fields(s, u.fields);
            s << "  Direct local group membership evidence:";
            for (const auto &g : u.groups)
                s << ' ' << quote(g);
            s << '\n';
        }
    }
    if (show(o, "groups")) {
        s << "\nLocal groups and membership evidence\n";
        for (const auto &g : r.groups) {
            s << quote(g.name) << " (privileged classification: "
              << (g.fields.count("privileged_classification") &&
                          g.fields.at("privileged_classification").status == "available"
                      ? (g.privileged ? "yes" : "no")
                      : "unknown")
              << ")\n";
            human_fields(s, g.fields);
            for (const auto &m : g.members)
                s << "  member: " << quote(m.sid) << " " << m.kind << " "
                  << (m.name.status == "available" ? quote(m.name.value) : m.name.status) << '\n';
        }
    }
    if (show(o, "policy")) {
        s << "\nMachine account/password policy\n";
        human_fields(s, r.policy);
    }
    s << "\nFindings\n";
    for (const auto &f : r.findings)
        s << f.code << " [" << quote(f.subject) << "] " << quote(f.evidence) << '\n';
    s << "\nUnavailable information\n";
    s << "Custom group SIDs and non-inventory member identities are intentionally unavailable; use --groups "
         "for details.\n";
    for (const auto &i : r.issues)
        s << i.source << " [" << quote(i.subject) << "] " << i.status << " Win32=" << i.code << '\n';
    s << "\nMembership is direct evidence only; tokens, UAC and rights are not evaluated.\nLast logon is not "
         "proof of abandonment. Password flags do not measure password strength.\n";
    return s.str();
}
Options parse(const std::vector<std::wstring> &args) {
    Options o;
    bool view = false;
    for (size_t i = 0; i < args.size(); ++i) {
        const auto &a = args[i];
        if (a == L"--json") {
            if (o.json)
                throw std::invalid_argument("Duplicate --json");
            o.json = true;
        } else if (a == L"--help")
            o.help = true;
        else if (a == L"--version")
            o.version = true;
        else if (a == L"--summary" || a == L"--users" || a == L"--groups" || a == L"--policy" ||
                 a == L"--user") {
            if (view)
                throw std::invalid_argument("Choose one view");
            view = true;
            o.view = utf8(a.substr(2));
            if (a == L"--user") {
                ++i;
                if (i == args.size() || args[i].empty() || args[i].rfind(L"--", 0) == 0)
                    throw std::invalid_argument("--user requires a local account name");
                o.user = args[i];
            }
        } else
            throw std::invalid_argument("Unknown argument");
    }
    if ((o.help || o.version) && args.size() != 1)
        throw std::invalid_argument("Help/version must be used alone");
    return o;
}
int result(const Report &r) { return r.issues.empty() ? 0 : 2; }
const char *help() {
    return "windows-local-account-auditor 1.0.0\nUsage: windows-local-account-auditor "
           "[--summary|--users|--groups|--policy|--user <name>] [--json]\n       "
           "windows-local-account-auditor --help|--version\nRead-only local configuration audit. No password "
           "testing or domain resolution.\nExit codes: 0 complete; 1 fatal; 2 partial acquisition; 3 invalid "
           "CLI; 4 local user not found.\n";
}
} // namespace audit
