#include "core.h"
#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <iostream>
#include <lm.h>
#include <memory>
#include <sddl.h>
#include <stdexcept>
#include <utility>
namespace {
void require(bool ok, const char *message) {
    if (!ok)
        throw std::runtime_error(message);
}
class Fixture final : public audit::Source {
  public:
    audit::Report acquire() override {
        audit::Report r;
        auto user = [](const std::string &name, const char *sid, bool enabled, const std::string &builtin) {
            audit::User u;
            u.name = name;
            u.fields = {{"sid", audit::Value::text(sid)},
                        {"built_in", audit::Value::text(builtin)},
                        {"enabled", audit::Value::boolean(enabled)},
                        {"password_required", audit::Value::boolean(true)},
                        {"password_never_expires", audit::Value::boolean(false)},
                        {"account_expires", audit::Value::state("never")},
                        {"last_logon", audit::Value::state("unknown")},
                        {"logon_count", audit::Value::number(0)}};
            return u;
        };
        r.users.push_back(user("Z ordinary", "S-1-5-21-1-2-3-1001", true, "ordinary"));
        r.users.push_back(user(audit::utf8(L"Администратор"), "S-1-5-21-1-2-3-500", true, "Administrator"));
        r.users.push_back(user(audit::utf8(L"Invité"), "S-1-5-21-1-2-3-501", true, "Guest"));
        r.users.push_back(user("Disabled", "S-1-5-21-1-2-3-1002", false, "ordinary"));
        r.users[0].fields["password_never_expires"] = audit::Value::boolean(true);
        r.users[0].fields["password_required"] = audit::Value::boolean(false);
        r.users[0].fields["account_expires"] = audit::timestamp(1735689600, true);
        r.users[0].fields["description"] = audit::Value::text(audit::utf8(L"雪\n\"test\"\\\t"));
        audit::Group g;
        g.name = audit::utf8(L"Administrateurs");
        g.fields["sid"] = audit::Value::text("S-1-5-32-544");
        g.privileged = true;
        for (const auto &u : r.users)
            if (u.name != audit::utf8(L"Invité"))
                g.members.push_back({u.fields.at("sid").value, {}, {}});
        g.members.push_back({"S-1-5-21-9-8-7-2001", {}, {}});
        g.members.push_back({"S-1-5-32-545", {}, {}});
        r.groups.push_back(g);
        audit::Group nested;
        nested.name = audit::utf8(L"Utilisateurs");
        nested.fields["sid"] = audit::Value::text("S-1-5-32-545");
        nested.members.push_back({"S-1-5-21-1-2-3-501", {}, "unresolved"});
        r.groups.push_back(nested);
        r.policy["lockout_threshold"] = audit::Value::number(0);
        r.policy["minimum_password_length"] = audit::Value::number(14);
        r.policy["maximum_password_age_seconds"] = audit::duration(0xFFFFFFFFu);
        r.policy["lockout_duration_seconds"] = audit::Value::state("not_applicable");
        return r;
    }
};
size_t findings(const audit::Report &r, const char *code) {
    return static_cast<size_t>(std::count_if(r.findings.begin(), r.findings.end(),
                                             [code](const audit::Finding &f) { return f.code == code; }));
}
} // namespace
int main(int argc, char **argv) {
    try {
        Fixture fixture;
        auto r = fixture.acquire();
        audit::analyze(r);
        if (argc == 2 && std::string(argv[1]) == "--emit-json") {
            std::cout << audit::json(r, audit::Options{});
            return 0;
        }
        require(audit::local_role_allowed(SV_TYPE_SERVER), "local server accepted");
        require(!audit::local_role_allowed(SV_TYPE_DOMAIN_CTRL), "DC refused");
        require(!audit::local_role_allowed(SV_TYPE_DOMAIN_BAKCTRL | SV_TYPE_SERVER), "backup DC refused");
        const auto normal = audit::decode_account_flags(UF_NORMAL_ACCOUNT);
        require(normal.at("enabled").value == "true" && normal.at("password_required").value == "true",
                "ordinary flags");
        const auto unusual =
            audit::decode_account_flags(UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD | UF_DONT_EXPIRE_PASSWD |
                                        UF_PASSWD_CANT_CHANGE | UF_LOCKOUT);
        require(unusual.at("enabled").value == "false" && unusual.at("password_required").value == "false",
                "disabled/password not required flags");
        require(unusual.at("password_never_expires").value == "true" &&
                    unusual.at("user_may_change_password").value == "false" &&
                    unusual.at("locked_out").value == "true",
                "unusual flag combination");
        require(audit::rid_from_sid(nullptr).status == "unavailable", "missing SID");
        BYTE invalid[SECURITY_MAX_SID_SIZE]{};
        require(audit::rid_from_sid(invalid).status == "unavailable", "invalid SID");
        for (const auto &test :
             std::vector<std::pair<const wchar_t *, const char *>>{{L"S-1-5-21-1-2-3-500", "500"},
                                                                   {L"S-1-5-21-1-2-3-501", "501"},
                                                                   {L"S-1-5-21-1-2-3-1001", "1001"},
                                                                   {L"S-1-5-32-544", "544"}}) {
            PSID sid = nullptr;
            require(ConvertStringSidToSidW(test.first, &sid) != FALSE, "test SID parse");
            const std::unique_ptr<void, decltype(&LocalFree)> owner(sid, LocalFree);
            require(audit::rid_from_sid(sid).value == test.second, "SID RID extraction");
        }
        require(findings(r, "enabled_privileged_member") == 2, "enabled admins");
        require(findings(r, "disabled_privileged_member") == 1, "disabled privileged");
        require(findings(r, "multiple_enabled_administrators") == 1, "multiple admins");
        require(findings(r, "guest_enabled") == 1, "builtin Guest");
        const auto guest = std::find_if(r.users.begin(), r.users.end(), [](const audit::User &user) {
            return user.fields.at("built_in").value == "Guest";
        });
        require(guest != r.users.end() && guest->groups.size() == 1 &&
                    guest->groups[0] == audit::utf8(L"Utilisateurs"),
                "nested membership must not infer transitive access");
        require(findings(r, "password_never_expires") == 1, "never expires");
        require(findings(r, "password_not_required") == 1, "password flag");
        require(findings(r, "expiration_configured") == 1, "expiration");
        require(findings(r, "lockout_disabled") == 1, "lockout disabled");
        require(findings(r, "unresolved_member") == 1, "unresolved SID");
        require(r.groups[0].members[0].kind == "local_user", "SID matching");
        require(std::any_of(r.groups[0].members.begin(), r.groups[0].members.end(),
                            [](const audit::Member &m) { return m.kind == "local_group"; }),
                "nested group");
        require(audit::result(r) == 0, "complete exit");
        require(audit::timestamp(0, false).status == "unknown", "zero last logon");
        require(audit::timestamp(0xFFFFFFFFu, false).status == "unknown", "unlimited logon sentinel");
        require(audit::timestamp(0xFFFFFFFFu, true).status == "never", "never expiration");
        require(audit::timestamp(0, true).value == "0", "epoch expiration");
        require(audit::duration(0).value == "0", "zero age");
        require(audit::counter(0).value == "0", "zero counter");
        require(audit::counter(0xFFFFFFFFu).status == "unknown", "unknown counter sentinel");
        require(audit::duration(0xFFFFFFFFu).status == "unlimited", "unlimited age");
        require(audit::Value::boolean(false).status == "available", "false distinct");
        for (const auto *state : {"absent", "unavailable", "inaccessible", "unknown", "not_applicable"})
            require(audit::Value::state(state).value.empty(), "status null");
        require(audit::quote("\"\\\n\r\t\b\f\1") == "\"\\\"\\\\\\n\\r\\t\\b\\f\\u0001\"", "JSON escapes");
        audit::Options options;
        const auto original = audit::json(r, options);
        std::reverse(r.users.begin(), r.users.end());
        std::reverse(r.groups.begin(), r.groups.end());
        for (auto &g : r.groups)
            std::reverse(g.members.begin(), g.members.end());
        audit::analyze(r);
        require(audit::json(r, options) == original, "deterministic ordering");
        require(original.find("\"logon_count\":{\"status\":\"available\",\"value\":0}") != std::string::npos,
                "zero counts");
        require(original.find("\"schema_version\":\"1.0.0\"") != std::string::npos, "schema version");
        require(audit::parse({L"--json", L"--users"}).view == "users", "view parse");
        require(audit::parse({L"--user", L"雪"}).user == L"雪", "Unicode user");
        require(audit::parse({L"--help"}).help, "help");
        require(audit::parse({L"--version"}).version, "version");
        for (const auto &args : std::vector<std::vector<std::wstring>>{{L"--bad"},
                                                                       {L"--user"},
                                                                       {L"--users", L"--groups"},
                                                                       {L"--json", L"--json"},
                                                                       {L"--help", L"--json"},
                                                                       {L"--user", L"--json"}}) {
            bool rejected = false;
            try {
                audit::parse(args);
            } catch (const std::invalid_argument &) {
                rejected = true;
            }
            require(rejected, "invalid CLI rejection");
        }
        r.policy["lockout_threshold"] = audit::Value::number(5);
        r.policy["lockout_duration_seconds"] = audit::duration(1800);
        r.policy["lockout_observation_window_seconds"] = audit::duration(1800);
        audit::analyze(r);
        require(findings(r, "lockout_disabled") == 0, "finite lockout");
        r.users[0].fields["enabled"] = audit::Value::state("inaccessible");
        r.issues.push_back({"NetUserGetInfo(4)", r.users[0].name, "inaccessible", 5});
        audit::analyze(r);
        require(findings(r, "incomplete_information") == 1, "inaccessible finding");
        require(audit::result(r) == 2, "partial exit");
        require(r.users[0].fields.at("enabled").status == "inaccessible", "failure not false");
        require(findings(r, "privileged_member_state_unknown") == 1,
                "inaccessible account must not become disabled");
        r.users[0].fields["last_logon"] = audit::Value::state("unavailable");
        r.issues.push_back({"NetLocalGroupGetMembers(0)", r.groups[0].name, "inaccessible", 5});
        r.groups[0].fields["membership_status"] = audit::Value::state("inaccessible");
        audit::analyze(r);
        require(r.users[0].fields.at("membership_status").value == "partial_direct_evidence",
                "partial membership acquisition");
        require(audit::json(r, options).find("\"last_logon\":{\"status\":\"unavailable\",\"value\":null}") !=
                    std::string::npos,
                "unavailable last logon stays null");
        require(audit::result(r) == 2 && !r.groups[0].members.empty(),
                "partial acquisition retains observed members");
        std::cout << "All deterministic fixture checks passed\n";
        return 0;
    } catch (const std::exception &e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }
}
