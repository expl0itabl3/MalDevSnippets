#include <stdio.h>
#include <windows.h>
#include <psapi.h>

int main()
{
    // Get the handle to the current process
    HANDLE process = GetCurrentProcess();

    // Initialize MODULEINFO structure
    MODULEINFO mi = { 0 };

    // Get the handle to the loaded module ntdll.dll
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

    // Get the module information for ntdll.dll
    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));

    // Get the base address of ntdll.dll
    LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;

    // Create a handle to the ntdll file in the system32 directory
    HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    // Create a file mapping for the ntdll file
    HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);

    // Map a view of the ntdll file into the address space of the calling process
    LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

    // Get the DOS and NT headers of the ntdll module
    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

    // Iterate over the sections in the ntdll module
    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++)
    {
        // Get the section header for the current section
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        // Check if the current section is the .text section
        if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text"))
        {
            // Change the protection of the .text section to PAGE_EXECUTE_READWRITE
            DWORD oldProtection = 0;
            bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);

            // Copy the text section from the mapped view to the loaded module
            memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);

            // Restore the original protection of the text section
            isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
        }
    }

    // Close the handles and free the loaded module
    CloseHandle(process);
    CloseHandle(ntdllFile);
    CloseHandle(ntdllMapping);
    FreeLibrary(ntdllModule);

    return 0;
}
