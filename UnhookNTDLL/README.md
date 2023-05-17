# Unhooking NTDLL

This code is based on the [Full DLL Unhooking with C++](https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++) post by ired.team.

This C code unhooks the ntdll.dll library from the current process, which may help evade detection by certain Endpoint Detection and Response (EDR) systems. The code maps a fresh copy of ntdll.dll from disk to memory, finds the virtual address of the hooked ".text" section, copies the fresh .text section over the hooked one, and restores original memory protections. This results in the removal of any hooks, potentially allowing evasion of EDR systems that rely on userland API hooking.
