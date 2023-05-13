# Early Bird APC Injection

This example draws inspiration from [MaldevAcademy](https://maldevacademy.com/).

Early Bird APC Injection is a technique that injects a payload into a suspended process by utilizing Asynchronous Procedure Calls (APCs). By creating a suspended process and queuing the payload as an APC to its suspended thread, the payload is executed when the thread is resumed. This method leverages the thread's alertable state to trigger the execution of the injected payload. The following steps outline the procedure for executing this technique:
1. Invoke CreateProcessA, utilizing the CREATE_SUSPENDED flag to create a suspended process.
2. Store the payload within the memory of the newly created target process.
3. Obtain the handle of the suspended thread from the CreateProcess function, along with the base address of the payload, and provide them as arguments to QueueUserAPC.
4. Use the ResumeThread WinAPI function to resume the thread, thereby initiating the execution of the payload.

The payload itself consists of shellcode designed to launch the Windows calculator (calc.exe).
