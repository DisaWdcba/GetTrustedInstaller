# 🚀 Windows Privilege Escalation: 3 Ways to Get SYSTEM/TrustedInstaller

This repository demonstrates three reliable methods to escalate privileges to **SYSTEM** or **TrustedInstaller** level on Windows systems. These techniques are useful for penetration testers, security researchers, and system administrators who need to perform high-privilege operations.

## 🔍 Why These Methods Matter

Windows SYSTEM and TrustedInstaller accounts have the highest privileges in a Windows environment. Understanding how to properly obtain these privileges is essential for:
- Security testing and privilege escalation research
- Legitimate administrative tasks requiring full system access
- Understanding Windows security architecture

## 🛠️ Methods Overview

### 1. Token Impersonation (SYSTEM)
**Core Idea:** Steal a SYSTEM token from a privileged process like `winlogon.exe`  
✅ Most direct method  
✅ No persistent changes to system  
⚠️ Requires `SeDebugPrivilege`  

```c
// Example using winlogon.exe token
DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken);
CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, NULL, L"cmd.exe", CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
```

### 2. Scheduled Task (Highest Privileges)
**Core Idea:** Create a task running as SYSTEM with highest privileges  
✅ Works even with some privilege restrictions  
✅ Can launch GUI applications  
⚠️ Leaves temporary task artifact  

```c
// Task Scheduler API example
pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
RegisterTaskDefinition(L"HighPrivTask", pTask, TASK_CREATE_UPDATE, 
                      _variant_t(L"SYSTEM"), _variant_t(), 
                      TASK_LOGON_SERVICE_ACCOUNT, _variant_t(L""));
```

### 3. Service Control Manager (SYSTEM)
**Core Idea:** Create/control a service running as SYSTEM  
✅ Most reliable for background operations  
✅ Can be made persistent  
⚠️ Requires service creation privileges  

```c
// Service creation example
CreateServiceW(hSCManager, L"MyService", L"My Service", 
               SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
               SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
               L"C:\\path\\to\\binary.exe", NULL, NULL, NULL, NULL, NULL);
```


## 📚 Further Reading

- [Microsoft Token Documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [Task Scheduler Schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema)
- [Windows Service Security](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)


## 📜 License

MIT License - Use responsibly and ethically.
