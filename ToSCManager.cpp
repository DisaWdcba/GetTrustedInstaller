#include <string>
#include <iostream>
#include <codecvt>
#include <Windows.h>
#include <TlHelp32.h>

using namespace std;

void enable_privilege(const wstring& privilege_name)
{
    HANDLE token_handle;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token_handle))
    {
        throw runtime_error("OpenProcessToken failed: " + to_string(GetLastError()));
    }

    LUID luid;
    if (!LookupPrivilegeValue(nullptr, privilege_name.c_str(), &luid))
    {
        CloseHandle(token_handle);
        throw runtime_error("[*]LookupPrivilegeValue failed: " + to_string(GetLastError()));
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(token_handle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
    {
        CloseHandle(token_handle);
        throw runtime_error("[*]AdjustTokenPrivilege failed: " + to_string(GetLastError()));
    }

    if (GetLastError() != ERROR_SUCCESS)
    {
        CloseHandle(token_handle);
        throw runtime_error("[*]AdjustTokenPrivilege did not apply the privilege correctly.");
    }

    CloseHandle(token_handle);
    wcout << L"[*]Enabled privilege: " << privilege_name << endl;
}

DWORD get_process_id_by_name(const wstring process_name)
{
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot_handle == INVALID_HANDLE_VALUE)
    {
        throw runtime_error("[*]CreateToolhelp32Snapshot failed: " + to_string(GetLastError()));
    }

    DWORD pid = -1;
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(snapshot_handle, &pe))
    {
        do
        {
            if (process_name == pe.szExeFile)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot_handle, &pe));
    }

    CloseHandle(snapshot_handle);

    if (pid == -1)
    {
        throw runtime_error("process not found: " + wstring_convert<codecvt_utf8<wchar_t>>{}.to_bytes(process_name));
    }

    wcout << L"Found process ID for " << process_name << L": " << pid << endl;
    return pid;
}

void impersonate_system()
{
    const auto system_pid = get_process_id_by_name(L"winlogon.exe");
    HANDLE process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, system_pid);
    if (process_handle == nullptr)
    {
        throw runtime_error("[*]OpenProcess failed (winlogon.exe): " + to_string(GetLastError()));
    }

    HANDLE token_handle;
    if (!OpenProcessToken(process_handle, TOKEN_DUPLICATE, &token_handle))
    {
        CloseHandle(process_handle);
        throw runtime_error("[*]OpenProcessToken failed (winlogon.exe): " + to_string(GetLastError()));
    }
    CloseHandle(process_handle);

    HANDLE dup_token_handle;
    SECURITY_ATTRIBUTES token_attributes = { sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE };
    if (!DuplicateTokenEx(token_handle, TOKEN_ALL_ACCESS, &token_attributes, SecurityImpersonation, TokenImpersonation, &dup_token_handle))
    {
        CloseHandle(token_handle);
        throw runtime_error("[*]DuplicateTokenEx failed (winlogon.exe): " + to_string(GetLastError()));
    }
    CloseHandle(token_handle);

    if (!ImpersonateLoggedOnUser(dup_token_handle))
    {
        CloseHandle(dup_token_handle);
        throw runtime_error("[*]ImpersonateLoggedOnUser failed: " + to_string(GetLastError()));
    }
    CloseHandle(dup_token_handle);

    wcout << L"[*]Successfully impersonated the System account." << endl;
}

int start_trusted_installer_service()
{
    SC_HANDLE sc_manager_handle = OpenSCManager(nullptr, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
    if (sc_manager_handle == nullptr)
    {
        throw runtime_error("[*]OpenSCManager failed: " + to_string(GetLastError()));
    }

    SC_HANDLE service_handle = OpenServiceW(sc_manager_handle, L"TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START);
    if (service_handle == nullptr)
    {
        CloseServiceHandle(sc_manager_handle);
        throw runtime_error("[*]OpenService failed: " + to_string(GetLastError()));
    }
    CloseServiceHandle(sc_manager_handle);

    SERVICE_STATUS_PROCESS status_buffer;
    DWORD bytes_needed;
    while (QueryServiceStatusEx(service_handle, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status_buffer), sizeof(SERVICE_STATUS_PROCESS), &bytes_needed))
    {
        if (status_buffer.dwCurrentState == SERVICE_STOPPED)
        {
            if (!StartServiceW(service_handle, 0, nullptr))
            {
                CloseServiceHandle(service_handle);
                throw runtime_error("StartService failed: " + to_string(GetLastError()));
            }
            wcout << L"[*]Started TrustedInstaller service." << endl;
        }
        else if (status_buffer.dwCurrentState == SERVICE_RUNNING)
        {
            wcout << L"[*]TrustedInstaller service is already running." << endl;
            break;
        }
        else if (status_buffer.dwCurrentState == SERVICE_START_PENDING || status_buffer.dwCurrentState == SERVICE_STOP_PENDING)
        {
            Sleep(status_buffer.dwWaitHint);
            continue;
        }
    }

    if (status_buffer.dwCurrentState != SERVICE_RUNNING)
    {
        CloseServiceHandle(service_handle);
        throw runtime_error("[*]Failed to start TrustedInstaller service.");
    }

    DWORD pid = status_buffer.dwProcessId;
    CloseServiceHandle(service_handle);
    wcout << L"[*]TrustedInstaller service PID: " << pid << endl;
    return pid;
}

void create_process_as_trusted_installer(const DWORD pid, const wstring& command_line)
{
    enable_privilege(L"SeDebugPrivilege");
    enable_privilege(L"SeImpersonatePrivilege");

    impersonate_system();

    HANDLE process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process_handle == nullptr)
    {
        throw runtime_error("[*]OpenProcess failed (TrustedInstaller.exe): " + to_string(GetLastError()));
    }

    HANDLE token_handle;
    if (!OpenProcessToken(process_handle, TOKEN_DUPLICATE, &token_handle))
    {
        CloseHandle(process_handle);
        throw runtime_error("[*]OpenProcessToken failed (TrustedInstaller.exe): " + to_string(GetLastError()));
    }
    CloseHandle(process_handle);

    HANDLE dup_token_handle;
    SECURITY_ATTRIBUTES token_attributes = { sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE };
    if (!DuplicateTokenEx(token_handle, TOKEN_ALL_ACCESS, &token_attributes, SecurityImpersonation, TokenImpersonation, &dup_token_handle))
    {
        CloseHandle(token_handle);
        throw runtime_error("[*]DuplicateTokenEx failed (TrustedInstaller.exe): " + to_string(GetLastError()));
    }
    CloseHandle(token_handle);

    STARTUPINFOW startup_info = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION process_info;
    ZeroMemory(&process_info, sizeof(PROCESS_INFORMATION));
    if (!CreateProcessWithTokenW(dup_token_handle, LOGON_WITH_PROFILE, nullptr, const_cast<LPWSTR>(command_line.c_str()), CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &startup_info, &process_info))
    {
        CloseHandle(dup_token_handle);
        throw runtime_error("[*]CreateProcessWithTokenW failed: " + to_string(GetLastError()));
    }
    CloseHandle(dup_token_handle);

    wcout << L"[*]Success: Process created with elevated privileges." << endl;
    WaitForSingleObject(process_info.hProcess, INFINITE);
    CloseHandle(process_info.hProcess);
    CloseHandle(process_info.hThread);
}

int main(int argc, wchar_t* argv[])
{
    wstring command_line;
    if (argc == 1)
    {
        command_line = L"del.exe"; //切换成你想要启动的进程
    }
    else if (argc == 2)
    {
        command_line = argv[1];
    }
    else
    {
        wcerr << L"[*]Error: invalid argument." << endl;
        return 1;
    }

    try
    {
        wcout << L"[*]Starting TrustedInstaller service..." << endl;
        const auto pid = start_trusted_installer_service();
        wcout << L"[*]Creating process as TrustedInstaller..." << endl;
        create_process_as_trusted_installer(pid, command_line);
        wcout << L"[*]Process creation completed." << endl;
    }
    catch (const exception& e)
    {
        wcerr << L"Exception: " << e.what() << endl;
        return 1;
    }
    wcout << L"Waiting for the created process to exit..." << endl;
    while (true)
    {
        Sleep(1000); 
    }
    system("pause");
    return 0;
}
