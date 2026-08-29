#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <winhttp.h>

#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "psapi.lib")

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out += c;
    }
    return out;
}

static std::vector<std::string> scan_processes() {
    const std::vector<std::string> indicators = {
        "cheatengine.exe",
        "ollydbg.exe",
        "x64dbg.exe",
        "x32dbg.exe"
    };

    std::vector<std::string> hits;
    DWORD processes[2048]{};
    DWORD needed = 0;

    if (!EnumProcesses(processes, sizeof(processes), &needed))
        return hits;

    const DWORD count = needed / sizeof(DWORD);

    for (DWORD i = 0; i < count; ++i) {
        if (processes[i] == 0) continue;

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            processes[i]
        );
        if (!hProcess) continue;

        char name[MAX_PATH]{};
        if (GetModuleBaseNameA(hProcess, nullptr, name, MAX_PATH)) {
            std::string processName = lower(name);

            for (const auto& indicator : indicators) {
                if (processName == indicator) {
                    if (std::find(hits.begin(), hits.end(), processName) == hits.end())
                        hits.push_back(processName);
                }
            }
        }

        CloseHandle(hProcess);
    }

    return hits;
}

static bool post_result(const std::string& checkId,
                        const std::string& status,
                        const std::string& details) {
    HINTERNET session = WinHttpOpen(
        L"FARALAG-AC-Scanner/3.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!session) return false;

    HINTERNET connect = WinHttpConnect(
        session, L"faralag.ro", INTERNET_DEFAULT_HTTPS_PORT, 0
    );
    if (!connect) {
        WinHttpCloseHandle(session);
        return false;
    }

    HINTERNET request = WinHttpOpenRequest(
        connect,
        L"POST",
        L"/ac/api/submit.php",
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );

    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    std::string body =
        "{\"check_id\":\"" + json_escape(checkId) +
        "\",\"status\":\"" + json_escape(status) +
        "\",\"details\":\"" + json_escape(details) + "\"}";

    const wchar_t* headers = L"Content-Type: application/json\r\n";

    BOOL ok = WinHttpSendRequest(
        request,
        headers,
        static_cast<DWORD>(-1L),
        body.data(),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0
    );

    if (ok)
        ok = WinHttpReceiveResponse(request, nullptr);

    DWORD httpStatus = 0;
    DWORD size = sizeof(httpStatus);

    if (ok) {
        WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &httpStatus,
            &size,
            WINHTTP_NO_HEADER_INDEX
        );
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    return ok && httpStatus >= 200 && httpStatus < 300;
}

int main(int argc, char** argv) {
    std::cout << "========================================\n";
    std::cout << "        FARALAG AC SCANNER 3.0\n";
    std::cout << "========================================\n\n";

    std::string checkId;

    if (argc >= 2) {
        checkId = argv[1];
    } else {
        std::cout << "Check ID (ex. FAC-29110660A0): ";
        std::getline(std::cin, checkId);
    }

    std::transform(checkId.begin(), checkId.end(), checkId.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    if (checkId.rfind("FAC-", 0) != 0 || checkId.size() < 8) {
        std::cout << "\nInvalid Check ID.\n";
        std::cout << "Press Enter to close...";
        std::string pause;
        std::getline(std::cin, pause);
        return 1;
    }

    std::cout << "Check ID: " << checkId << "\n\n";

    std::cout << "[1/3] Scanning Windows processes...\n";
    const auto hits = scan_processes();

    const std::string status = hits.empty() ? "CLEAN" : "SUSPICIOUS";

    std::ostringstream details;
    details << "Process scan completed.";
    if (!hits.empty()) {
        details << " Indicators:";
        for (const auto& h : hits)
            details << " " << h;
    }

    std::cout << "[2/3] Preparing report...\n";
    std::cout << "[3/3] Uploading report...\n";

    const bool uploaded = post_result(checkId, status, details.str());

    std::cout << "\n========================================\n";
    std::cout << "RESULT: " << status << "\n";
    std::cout << "========================================\n";

    if (!hits.empty()) {
        std::cout << "\nSuspicious indicators found:\n";
        for (const auto& h : hits)
            std::cout << " - " << h << "\n";
    }

    if (uploaded) {
        std::cout << "\nReport uploaded successfully.\n";
        std::cout << "https://faralag.ro/ac/check/?id=" << checkId << "\n";
    } else {
        std::cout << "\nCould not upload report to FARALAG AC API.\n";
    }

    std::cout << "\nPress Enter to close...";
    std::string pause;
    std::getline(std::cin, pause);

    return uploaded ? 0 : 2;
}
