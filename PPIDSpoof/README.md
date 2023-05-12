# PPIDSpoof

This example draws inspiration from [MaldevAcademy](https://maldevacademy.com/).

PPID spoofing is a technique employed to conceal the true relationship between a child process and its genuine parent process by altering the Parent Process ID (PPID) of the former. The following steps outline the procedure for executing this technique:

1. Invoke CreateProcessA, utilizing the EXTENDED_STARTUPINFO_PRESENT flag, to acquire additional control over the created process.
2. Construct the STARTUPINFOEXA structure, which encompasses the list of attributes (LPPROC_THREAD_ATTRIBUTE_LIST).
3. Call InitializeProcThreadAttributeList twice. The first call determines the size of the list, while the second one carries out the actual initialization.
4. Utilize UpdateProcThreadAttribute to modify the attributes, specifically setting the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS flag to designate the parent process of the thread.

To facilitate the process, I implemented the "FindSvchostProcess" function, which locates instances of the svchost process. Subsequently, the code invokes CreatePPidSpoofedProcess() to generate a new process (e.g., "notepad.exe") with the spoofed parent process designated as "svchost.exe".
