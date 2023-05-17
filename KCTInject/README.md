# KCT Injection

This code is based on the [KernelCallbackTable-Injection](https://github.com/capt-meelo/KernelCallbackTable-Injection) project by capt-meelo.

This example injects a payload into a sacrificial process (notepad.exe) by modifying the Kernel Callback Table (KCT) of the process. The following steps outline the procedure for executing this technique:
1. Create a hidden notepad.exe process.
2. Retrieve the window handle and process ID of the hidden notepad.exe process.
3. Open the process with full access privileges.
4. Read the addresses of the Process Environment Block (PEB) and Kernel Callback Table (KCT) of the hidden process.
5. Write the payload to the remote process.
6. Allocate memory for the new KCT.
7. Update the address of the Kernel Callback Table in the Process Environment Block (PEB).
8. Trigger the execution of the payload using a WM_COPYDATA message.

The payload itself consists of shellcode designed to launch the Windows calculator (calc.exe).
