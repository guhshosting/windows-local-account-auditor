#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>
namespace audit {
struct Value {
    std::string status = "unavailable";
    std::string value;
    bool numeric = false;
    static Value text(std::string v);
    static Value number(std::uint64_t v);
    static Value boolean(bool v);
    static Value state(std::string s);
};
using Fields = std::map<std::string, Value>;
struct User {
    User() = default;
    User(const User &) = default;
    User &operator=(const User &) = default;
    std::string name;
    Fields fields;
    std::vector<std::string> groups;
};
struct Member {
    std::string sid;
    Value name;
    std::string kind = "unresolved";
};
struct Group {
    Group() = default;
    Group(const Group &) = default;
    Group &operator=(const Group &) = default;
    std::string name;
    Fields fields;
    std::vector<Member> members;
    bool privileged = false;
};
struct Issue {
    std::string source, subject, status;
    std::uint32_t code = 0;
};
struct Finding {
    std::string code, subject, evidence;
};
struct Report {
    Report() = default;
    Report(const Report &) = default;
    Report &operator=(const Report &) = default;
    std::vector<User> users;
    std::vector<Group> groups;
    Fields policy, metadata;
    std::vector<Issue> issues;
    std::vector<Finding> findings;
};
struct Options {
    std::string view = "all";
    std::wstring user;
    bool json = false, help = false, version = false;
};
class Source {
  public:
    virtual ~Source() = default;
    virtual Report acquire() = 0;
};
std::string utf8(const std::wstring &value);
std::string quote(const std::string &value);
Value timestamp(std::uint32_t value, bool expiration);
Value duration(std::uint32_t value);
Value counter(std::uint32_t value);
Value rid_from_sid(void *sid);
Fields decode_account_flags(std::uint32_t flags);
bool local_role_allowed(std::uint32_t server_type);
void analyze(Report &report);
std::string json(const Report &report, const Options &options);
std::string human(const Report &report, const Options &options);
Options parse(const std::vector<std::wstring> &args);
int result(const Report &report);
Report acquire_windows();
const char *help();
} // namespace audit
