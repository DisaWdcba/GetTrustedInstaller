#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <stdio.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
BOOL RunAsHighest(LPCTSTR lpApplication) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("CoInitializeEx failed: 0x%08X\n", hr);
        return FALSE;
    }
    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        printf("CoCreateInstance failed: 0x%08X\n", hr);
        CoUninitialize();
        return FALSE;
    }

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        printf("ITaskService::Connect failed: 0x%08X\n", hr);
        pService->Release();
        CoUninitialize();
        return FALSE;
    }

    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        printf("GetFolder failed: 0x%08X\n", hr);
        pService->Release();
        CoUninitialize();
        return FALSE;
    }
    ITaskDefinition* pTask = NULL;
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) {
        printf("NewTask failed: 0x%08X\n", hr);
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return FALSE;
    }
    IPrincipal* pPrincipal = NULL;
    hr = pTask->get_Principal(&pPrincipal);
    if (SUCCEEDED(hr)) {
        pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
        pPrincipal->Release();
    }
    else {
        printf("get_Principal failed: 0x%08X\n", hr);
    }
    IActionCollection* pActionCollection = NULL;
    hr = pTask->get_Actions(&pActionCollection);
    if (SUCCEEDED(hr)) {
        IAction* pAction = NULL;
        hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
        if (SUCCEEDED(hr)) {
            IExecAction* pExecAction = NULL;
            hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
            if (SUCCEEDED(hr)) {
                pExecAction->put_Path(_bstr_t(lpApplication));
                pExecAction->Release();
            }
            else {
                printf("QueryInterface(IExecAction) failed: 0x%08X\n", hr);
            }
            pAction->Release();
        }
        else {
            printf("Create(TASK_ACTION_EXEC) failed: 0x%08X\n", hr);
        }
        pActionCollection->Release();
    }
    else {
        printf("get_Actions failed: 0x%08X\n", hr);
    }
    IRegisteredTask* pRegisteredTask = NULL;
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(L"TempHighPrivilegeTask"),
        pTask,
        TASK_CREATE_OR_UPDATE,
        _variant_t(L"SYSTEM"),  
        _variant_t(),
        TASK_LOGON_SERVICE_ACCOUNT,
        _variant_t(L""),
        &pRegisteredTask);

    if (FAILED(hr)) {
        printf("RegisterTaskDefinition failed: 0x%08X\n", hr);
    }
    else {
        IRunningTask* pRunningTask = NULL;
        hr = pRegisteredTask->Run(_variant_t(), &pRunningTask);
        if (SUCCEEDED(hr)) {
            printf("Task started successfully.\n");
            pRunningTask->Release();
        }
        else {
            printf("Run failed: 0x%08X\n", hr);
        }
        pRegisteredTask->Release();
    }
    pTask->Release();
    pRootFolder->Release();
    pService->Release();
    CoUninitialize();

    return SUCCEEDED(hr);
}

int main() {
    LPCTSTR appPath = TEXT("C:\\Windows\\System32\\cmd.exe");

    if (RunAsHighest(appPath)) {
        printf("Program executed with highest privileges!\n");
    }
    else {
        printf("Failed to execute with highest privileges.\n");
    }

    return 0;
}
