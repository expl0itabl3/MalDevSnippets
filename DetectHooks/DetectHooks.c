#include <stdio.h>
#include <windows.h>
#include <psapi.h>

/*
 * This code is based on the "Detecting Hooked Syscalls" post by ired.team
 * Source code available at: https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions
*/

int main()
{
    // Initialize pointer to NULL
    PDWORD functionAddress = NULL;

    // Load ntdll library
    HMODULE libraryBase = LoadLibraryA("ntdll.dll");
    if (!libraryBase)
    {
        printf("Failed to load ntdll.dll\n");
        return 1;
    }

    // Obtain DOS header of the ntdll library
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;

    // Obtain NT headers from the DOS header
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

    // Obtain the Relative Virtual Address (RVA) of the export directory from the NT headers
    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // Obtain the export directory from the RVA
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

    // Obtain the RVAs of the functions, names, and name ordinals from the export directory
    PDWORD addressOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

    // Define the syscall prologue
    unsigned char syscallPrologue[4] = {0x4c, 0x8b, 0xd1, 0xb8};

    // Define an array of function names that are known to produce false positives
    char *excludedFunctions[] = {
        "NtGetTickCount",
        "NtQuerySystemTime",
        "NtdllDefWindowProc_A",
        "NtdllDefWindowProc_W",
        "NtdllDialogWndProc_A",
        "NtdllDialogWndProc_W",
        "ZwQuerySystemTime"};
    int numExcludedFunctions = sizeof(excludedFunctions) / sizeof(excludedFunctions[0]);

    int hookedFunctionFound = 0;

    // Iterate over the exported functions
    for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++)
    {
        // Get function name and function address
        DWORD functionNameRVA = addressOfNamesRVA[i];
        char *functionName = (char *)((DWORD_PTR)libraryBase + functionNameRVA);
        DWORD functionAddressRVA = addressOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
        functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);

        // Skip the function if it's in the list of excluded functions
        int isExcluded = 0;
        for (int j = 0; j < numExcludedFunctions; j++)
        {
            if (strcmp(functionName, excludedFunctions[j]) == 0)
            {
                isExcluded = 1;
                break;
            }
        }
        if (isExcluded)
            continue;

        // Only process the function if it starts with "Nt" or "Zw"
        if (strncmp(functionName, "Nt", 2) == 0 || strncmp(functionName, "Zw", 2) == 0)
        {
            // If the function doesn't start with the syscall prologue, then it may be hooked
            if (memcmp(functionAddress, syscallPrologue, 4) != 0)
            {
                // If the first byte is a jmp instruction (0xE9), then the function is definitely hooked
                if (*((unsigned char *)functionAddress) == 0xE9)
                {
                    // Calculate the jump target relative to the next instruction
                    DWORD jumpTargetRelative = *((PDWORD)((char *)functionAddress + 1));
                    // Calculate the absolute jump target address
                    PDWORD jumpTarget = functionAddress + 5 + jumpTargetRelative;
                    // Buffer for storing the module name
                    char moduleNameBuffer[512];
                    // Get the module name where the jump leads to
                    GetMappedFileNameA(GetCurrentProcess(), jumpTarget, moduleNameBuffer, 512);
                    // Print out the hooked function information
                    printf("Hooked: %s : %p into module %s\n", functionName, functionAddress, moduleNameBuffer);
                    // Set the flag indicating a hooked function has been found
                    hookedFunctionFound = 1;
                }
                else
                {
                    // If the function doesn't start with a jmp instruction, then it's potentially hooked
                    printf("Potentially hooked: %s : %p\n", functionName, functionAddress);
                    // Set the flag indicating a hooked function has been found
                    hookedFunctionFound = 1;
                }
            }
        }
    }

    // If no hooked function was found, print a message indicating that
    if (!hookedFunctionFound)
    {
        printf("No hooked functions found.\n");
    }

    return 0;
}
