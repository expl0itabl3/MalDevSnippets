# Remote Process Injection via CreateRemoteThread

Despite being widely recognized and susceptible to detection, CreateRemoteThread functions as a crucial foundation for process injection and code execution.

This C program performs code injection into a running process on a Windows machine. It identifies the target process ("notepad.exe") using the `FindProcessId` function, which checks all currently running processes to find the ID of the process with the matching name.

Upon successful identification of the target process, the `InjectCode` function performs the injection of the payload into the process following these steps:
1. It opens the target process using its process ID.
2. It then allocates a region in the target process's memory using `VirtualAllocEx`, which creates a space for the shellcode.
3. The shellcode is then written into this newly allocated memory space using `WriteProcessMemory`.
4. The memory region's protection is modified to `PAGE_EXECUTE_READ` using `VirtualProtectEx` to ensure the shellcode can be executed but not modified further.
5. `CreateRemoteThread` is then used to create a new thread in the target process that begins execution at the start of the injected shellcode.

The payload itself consists of shellcode designed to launch the Windows calculator (calc.exe).