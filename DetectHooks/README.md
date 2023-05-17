# Detecting Hooked Syscalls

This code is based on the "Detecting Hooked Syscalls" post by [ired.team](https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions).

The system calls (syscalls) or functions that are often the victims of API hooking usually commence with the prefixes `Nt` or `Zw`. In their unhooked state, these functions begin with the opcode sequence  `4c 8b d1 b8`.

By leveraging this knowledge, we can outline a process to determine if a function has been hooked:
* Iterate through all exported functions in the `ntdll.dll` library, a common target for such hooks due to its fundamental role in the Windows operating system.
* For each function, read the first four bytes, which correspond to the beginning of the syscall stub, and verify if these bytes match the sequence `4c 8b d1 b8`.
  * If the initial opcode sequence matches `4c 8b d1 b8`, the function appears to be unhooked, i.e., it is in its original state.
  * If the initial opcode sequence does not match `4c 8b d1 b8`, the function is likely hooked.
