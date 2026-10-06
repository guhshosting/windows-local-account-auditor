#include "core.h"
#include <Windows.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>
namespace {
void output(const std::string &text, DWORD channel) {
    const auto handle = GetStdHandle(channel);
    DWORD mode = 0;
    if (GetConsoleMode(handle, &mode)) {
        if (text.size() > INT_MAX)
            throw std::runtime_error("Output too large");
        const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                          static_cast<int>(text.size()), nullptr, 0);
        if (n == 0)
            throw std::runtime_error("Output conversion failed");
        std::wstring wide(static_cast<size_t>(n), L'\0');
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                                wide.data(), n) != n)
            throw std::runtime_error("Output conversion failed");
        size_t pos = 0;
        while (pos < wide.size()) {
            DWORD wrote = 0;
            const auto count = static_cast<DWORD>(std::min<size_t>(wide.size() - pos, 16000));
            if (!WriteConsoleW(handle, wide.data() + pos, count, &wrote, nullptr) || !wrote)
                throw std::runtime_error("Cannot write console");
            pos += wrote;
        }
    } else {
        size_t pos = 0;
        while (pos < text.size()) {
            DWORD wrote = 0;
            const auto count = static_cast<DWORD>(std::min<size_t>(text.size() - pos, 65536));
            if (!WriteFile(handle, text.data() + pos, count, &wrote, nullptr) || !wrote)
                throw std::runtime_error("Cannot write output");
            pos += wrote;
        }
    }
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    try {
        std::vector<std::wstring> args;
        for (int i = 1; i < argc; ++i)
            args.emplace_back(argv[i]);
        audit::Options options;
        try {
            options = audit::parse(args);
        } catch (const std::invalid_argument &e) {
            output(std::string(e.what()) + "\n" + audit::help(), STD_ERROR_HANDLE);
            return 3;
        }
        if (options.help) {
            output(audit::help(), STD_OUTPUT_HANDLE);
            return 0;
        }
        if (options.version) {
            output("windows-local-account-auditor 1.0.0\n", STD_OUTPUT_HANDLE);
            return 0;
        }
        auto report = audit::acquire_windows();
        const int exit_code = audit::result(report);
        if (options.view == "user") {
            const auto desired = audit::utf8(options.user);
            std::string found;
            for (const auto &u : report.users) {
                const int n =
                    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, u.name.c_str(), -1, nullptr, 0);
                if (n <= 0)
                    continue;
                std::wstring wide(static_cast<size_t>(n), L'\0');
                if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, u.name.c_str(), -1, wide.data(), n) !=
                    n)
                    continue;
                if (CompareStringOrdinal(wide.c_str(), -1, options.user.c_str(), -1, TRUE) == CSTR_EQUAL) {
                    found = u.name;
                    break;
                }
            }
            if (found.empty()) {
                output("Local user not found in acquired inventory: " + audit::quote(desired) +
                           (exit_code == 2 ? " (inventory may be incomplete)" : "") + "\n",
                       STD_ERROR_HANDLE);
                return exit_code == 2 ? 2 : 4;
            }
            report.users.erase(std::remove_if(report.users.begin(), report.users.end(),
                                              [&found](const audit::User &u) { return u.name != found; }),
                               report.users.end());
            report.findings.erase(std::remove_if(report.findings.begin(), report.findings.end(),
                                                 [&found](const audit::Finding &f) {
                                                     return f.subject != found && f.subject != "machine";
                                                 }),
                                  report.findings.end());
        }
        output(options.json ? audit::json(report, options) : audit::human(report, options),
               STD_OUTPUT_HANDLE);
        return exit_code;
    } catch (const std::exception &e) {
        try {
            output(std::string("Fatal: ") + e.what() + "\n", STD_ERROR_HANDLE);
        } catch (...) {
            return 1; /* stderr failed; preserve fatal result */
        }
        return 1;
    }
}
