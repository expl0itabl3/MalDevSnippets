#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Function to create a new process with a spoofed parent process ID
BOOL CreatePPidSpoofedProcess(IN HANDLE hParentProcess, IN LPCWSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread)
{
    // Process and thread attributes
    WCHAR lpPath[MAX_PATH * 2];
    WCHAR WnDr[MAX_PATH];
    SIZE_T sThreadAttList = NULL;
    PPROC_THREAD_ATTRIBUTE_LIST pThreadAttList = NULL;

    STARTUPINFOEXA SiEx = { 0 };
    PROCESS_INFORMATION Pi = { 0 };

    // Zero the memory for STARTUPINFOEXA and PROCESS_INFORMATION
    RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // Get the Windows directory path
    if (!GetEnvironmentVariableW(L"WINDIR", WnDr, MAX_PATH))
    {
        wprintf(L"[!] GetEnvironmentVariableW failed with Error : %d \n", GetLastError());
        return FALSE;
    }

    // Construct the full path of the process to be started
    swprintf(lpPath, sizeof(lpPath) / sizeof(WCHAR), L"%s\\System32\\%s", WnDr, lpProcessName);

    // Get the required size for pThreadAttList
    InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);

    // Allocate memory for pThreadAttList
    pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
    if (pThreadAttList == NULL)
    {
        printf("[!] HeapAlloc failed with Error : %d \n", GetLastError());
        return FALSE;
    }

    // Initialize pThreadAttList
    if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList))
    {
        printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Set the parent process attribute
    if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL))
    {
        printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Assign the updated pThreadAttList to lpAttributeList in SiEx
    SiEx.lpAttributeList = pThreadAttList;

    // Create a new process with the specified parent process
    if (!CreateProcessW(NULL, lpPath, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, L"C:\\Windows\\System32", &SiEx.StartupInfo, &Pi))
    {
        printf("[!] CreateProcessW Failed with Error : %d \n", GetLastError());
        return FALSE;
    }

    // Get the identifiers of the new process
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    // Clean up: delete the pThreadAttList and close the handle to the parent process
    DeleteProcThreadAttributeList(pThreadAttList);
    CloseHandle(hParentProcess);

    // Check if the process identifiers are valid, if so return TRUE
    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;
}

// Function to find a process named "svchost.exe"
HANDLE FindSvchostProcess()
{
    // Take a snapshot of all processes in the system
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        wprintf(L"Failed to create snapshot: %d\n", GetLastError());
        return NULL;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Retrieve information about the first process
    if (!Process32FirstW(hSnapshot, &pe32))
    {
        wprintf(L"Failed to get first process: %d\n", GetLastError());
        CloseHandle(hSnapshot);
        return NULL;
    }

    // Walk the snapshot of processes and find svchost.exe
    do
    {
        if (wcscmp(pe32.szExeFile, L"svchost.exe") == 0)
        {
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProcess == NULL)
            {
                DWORD errorCode = GetLastError();
                if (errorCode == ERROR_ACCESS_DENIED)
                {
                    wprintf(L"Insufficient privileges. Trying next process...\n");
                }
                else
                {
                    wprintf(L"Failed to open process: %d\n", errorCode);
                }
            }
            else
            {
                CloseHandle(hSnapshot);
                return hProcess;
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return NULL;
}

int main()
{
    // Find the "svchost.exe" process
    HANDLE hParentProcess = FindSvchostProcess();
    if (hParentProcess == NULL)
    {
        wprintf(L"Failed to find svchost.exe process\n");
        return 1;
    }

    LPCWSTR lpProcessName = L"notepad.exe"; // Wide string literal
    DWORD dwProcessId;
    HANDLE hProcess;
    HANDLE hThread;

    // Create a new process with the spoofed parent process ID
    if (CreatePPidSpoofedProcess(hParentProcess, lpProcessName, &dwProcessId, &hProcess, &hThread))
    {
        wprintf(L"Process created successfully with ID: %lu\n", dwProcessId);
    }
    else
    {
        wprintf(L"Failed to create process\n");
    }

    return 0;
}
