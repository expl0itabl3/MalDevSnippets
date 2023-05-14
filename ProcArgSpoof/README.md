# Process Argument Spoofing

This example draws inspiration from [MaldevAcademy](https://maldevacademy.com/).

Process Argument Spoofing involves initiating a benign, suspended process and modifying the CommandLine.Buffer string within its Process Environment Block (PEB) with a payload. Upon resuming the process, logging services record the benign, not the actual, malicious arguments. The following steps outline the procedure for executing this technique:

1. Create a process in a suspended state.
2. Identify the remote PEB address of the created process.
3. Read the remote PEB and PEB->ProcessParameters structures.
4. Overwrite ProcessParameters.CommandLine.Buffer string with the payload to execute.
5. Resume the process.

Note that overwriting payloads using PEB->ProcessParameters.CommandLine.Buffer can be detected by tools like Process Hacker and 
Process Explorer. These tools employ NtQueryInformationProcess to read runtime process command line arguments. However, you can trick these tools by adjusting CommandLine.Length to be less than the buffer size in the remote process. This strategy limits the accessible buffer segment for external tools, effectively hiding the payload.
