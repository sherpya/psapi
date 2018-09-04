/*
 *  KernelEx
 *  Copyright (C) 2008, Tihiy
 *  Copyright (C) 2018, Gianluigi Tiesi <sherpya@netfarm.it>
 *
 *  This file is part of KernelEx source code.
 *
 *  KernelEx is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation; version 2 of the License.
 *
 *  KernelEx is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GNU Make; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#define PDB32_WIN16_PROC 0x0008 /* Win16 process */

typedef DWORD(WINAPI * GPF)(DWORD ProcessID);
typedef DWORD(WINAPI * MPH)(HANDLE hProcess);

static MPH pfMapProcessHandle = NULL;
static GPF pfGetProcessFlags = NULL;

#ifdef __GNUC__
#define DllMain DllMainCRTStartup
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		HMODULE k32;
		DWORD *faddr, addr;

		DisableThreadLibraryCalls(hinstDLL);
		k32 = GetModuleHandle("kernel32.dll");
		pfGetProcessFlags = (GPF) GetProcAddress(k32, "GetProcessFlags");
		if (!pfGetProcessFlags)
		{
			MessageBoxA(NULL, "GetProcessFlags not found in kernel32.dll", "PSAPI init error", MB_OK | MB_ICONERROR);
			return FALSE;
		}

		// there is jmp _SetFilePointer
		faddr = (DWORD *)((DWORD) GetProcAddress(k32, "SetFilePointer") + 0x1d);
		// 0x16 bytes before _SetFilePointer there is MapProcessHandle, just what we need
		addr = (DWORD) faddr + *faddr + 4 - 0x16;
		faddr = (DWORD *) addr;
		if (*faddr != 0x206A006A) // push 0; push 0x20
		{
			// try hardcoded Win98SE
			addr = 0xbff8c660;
			faddr = (DWORD *) addr;
			if (*faddr != 0x206A006A)
			{
				MessageBoxA(NULL, "Unable to find MapProcessHandle symbol", "PSAPI init error", MB_OK | MB_ICONERROR);
				return FALSE;
			}
		}
		pfMapProcessHandle = (MPH) addr;
	}
	return TRUE;
}

/* Retrieves the process identifier of the specified process.
dumb facts:
- most reliable relative code ever
- yes, kernel32 on XP+ does export this function. we make 98 too :p */
DWORD _GetProcessId(HANDLE hProcess)
{
	return pfMapProcessHandle(hProcess);
}

/* Enumerate processes in the system into array.
dumb facts:
- uses byte size instead of dword
- checks output buffers for access */
BOOL EnumProcesses(DWORD *pProcessIds, DWORD cb, DWORD *pBytesReturned)
{
	PROCESSENTRY32 oneprocess;
	HANDLE hSnap;

	if (cb < sizeof(DWORD))
		return FALSE;

	cb = cb & ~sizeof(DWORD); // you don't want to get a quarter of a process

	if (IsBadWritePtr(pProcessIds, sizeof(DWORD)) || IsBadWritePtr(pBytesReturned, sizeof(DWORD)))
	{
		SetLastError(ERROR_NOACCESS);
		return FALSE;
	}

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	oneprocess.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnap, &oneprocess))
	{
		*pProcessIds = oneprocess.th32ProcessID;
		pProcessIds++;
		*pBytesReturned = sizeof(DWORD);
		while (Process32Next(hSnap, &oneprocess) && *pBytesReturned < cb)
		{
			// skip 16-bit processes!
			if ((pfGetProcessFlags(oneprocess.th32ProcessID) & PDB32_WIN16_PROC) == 0)
			{
				*pProcessIds = oneprocess.th32ProcessID;
				pProcessIds++;
				*pBytesReturned += sizeof(DWORD);
			}
		}
	}
	CloseHandle(hSnap);
	return TRUE;
}

/* EPIC FAIL: Module32First may often not return actual exe hModule. We will work this around hardly! */
static DWORD FindProcessMID(HANDLE hSnap, DWORD pid)
{
	PROCESSENTRY32 oneprocess;
	oneprocess.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnap, &oneprocess);
	while (oneprocess.th32ProcessID != pid)
	{
		if (!Process32Next(hSnap, &oneprocess))
			return FALSE;
	}
	return oneprocess.th32ModuleID;
}

/* Enumerate module handles in a processes into array.
dumb facts:
- uses byte size instead of dword
- checks output buffers for access
- uses NOT the same rules as EnumProcesses: returns actually needed, not filled bytes! */
BOOL EnumProcessModules(HANDLE hProcess, HMODULE *lphModule, DWORD cb, DWORD *lpcbNeeded)
{
	MODULEENTRY32 onemodule;
	BOOL lRet;
	DWORD pid;
	DWORD ProcessModuleID;
	HMODULE *lphModuleStart;
	HANDLE hSnap;
	lphModuleStart = lphModule;

	if (cb < sizeof(DWORD))
		return FALSE;

	cb = cb & ~sizeof(DWORD); // you don't want to get a quarter of a module

	if (IsBadWritePtr(lphModule, sizeof(DWORD)) || IsBadWritePtr(lpcbNeeded, sizeof(DWORD)))
	{
		SetLastError(ERROR_NOACCESS);
		return FALSE;
	}

	pid = _GetProcessId(hProcess);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS, pid);
	if (hSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	ProcessModuleID = FindProcessMID(hSnap, pid);
	onemodule.dwSize = sizeof(MODULEENTRY32);
	lRet = Module32First(hSnap, &onemodule);
	*lpcbNeeded = 0;

	while (lRet)
	{
		if (cb > *lpcbNeeded)
		{
			if (onemodule.th32ModuleID == ProcessModuleID)
			{
				// current element gets first value, first gets current
				*lphModule = *lphModuleStart;
				*lphModuleStart = onemodule.hModule;
			}
			else
				*lphModule = onemodule.hModule;

			lphModule++;
		}
		else if (onemodule.th32ModuleID == ProcessModuleID)
			*lphModuleStart = onemodule.hModule;

		*lpcbNeeded += sizeof(DWORD);
		lRet = Module32Next(hSnap, &onemodule);
	}
	CloseHandle(hSnap);
	return TRUE;
}

/* find module/process full/short path in ansi/unicode */
static DWORD WINAPI GetModuleSuperName(
	HANDLE hProcess,
	HMODULE hModule,
	LPTSTR lpFilename,
	DWORD nSize,
	BOOL fUnicode,
	BOOL fFullName)
{
	MODULEENTRY32 onemodule;
	DWORD pid;
	DWORD ProcessModuleID = 0;
	HANDLE hSnap;
	LPCSTR ModuleName;

	if (!lpFilename || !nSize)
		return FALSE;

	pid = _GetProcessId(hProcess);
	onemodule.dwSize = sizeof(MODULEENTRY32);

	if (!hModule)
	{
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS, pid);
		if (hSnap == INVALID_HANDLE_VALUE)
			return FALSE;
		ProcessModuleID = FindProcessMID(hSnap, pid);
		if (!ProcessModuleID)
		{
			CloseHandle(hSnap);
			SetLastError(ERROR_INVALID_HANDLE);
			return FALSE;
		}
	}
	else
	{
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	}

	if (hSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	Module32First(hSnap, &onemodule);
	while (onemodule.hModule != hModule && onemodule.th32ModuleID != ProcessModuleID)
	{
		if (!Module32Next(hSnap, &onemodule)) // not found
		{
			CloseHandle(hSnap);
			return FALSE;
		}
	}

	CloseHandle(hSnap);
	ModuleName = fFullName ? onemodule.szExePath : onemodule.szModule;

	if (fUnicode)
		return MultiByteToWideChar(CP_ACP, 0, ModuleName, MAX_MODULE_NAME32, (LPWSTR)lpFilename, nSize);
	else
	{
		int maxLen = (nSize > MAX_MODULE_NAME32) ? MAX_MODULE_NAME32 : nSize;
		lstrcpynA(lpFilename, ModuleName, maxLen);
		return maxLen;
	}
}

DWORD GetModuleBaseNameA(HANDLE hProcess, HMODULE hModule, LPCSTR lpBaseName, DWORD nSize)
{
	return GetModuleSuperName(hProcess, hModule, (LPTSTR)lpBaseName, nSize, FALSE, FALSE);
}

DWORD GetModuleBaseNameW(HANDLE hProcess, HMODULE hModule, LPWSTR lpBaseName, DWORD nSize)
{
	return GetModuleSuperName(hProcess, hModule, (LPTSTR)lpBaseName, nSize, TRUE, FALSE);
}

DWORD GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPCSTR lpBaseName, DWORD nSize)
{
	return GetModuleSuperName(hProcess, hModule, (LPTSTR)lpBaseName, nSize, FALSE, TRUE);
}

DWORD GetModuleFileNameExW(HANDLE hProcess, HMODULE hModule, LPWSTR lpBaseName, DWORD nSize)
{
	return GetModuleSuperName(hProcess, hModule, (LPTSTR)lpBaseName, nSize, TRUE, TRUE);
}

/* BUGBUG those should return NT device path */
DWORD GetProcessImageFileNameA(HANDLE hProcess, LPCSTR lpImageFileName, DWORD nSize)
{
	return GetModuleSuperName(hProcess, NULL, (LPTSTR)lpImageFileName, nSize, FALSE, TRUE);
}

DWORD GetProcessImageFileNameW(HANDLE hProcess, LPWSTR lpImageFileName, DWORD nSize)
{
	return GetModuleSuperName(hProcess, NULL, (LPTSTR)lpImageFileName, nSize, TRUE, TRUE);
}

// rewrite those somehow, please...
BOOL GetProcessMemoryInfo(HANDLE Process, DWORD ppsmemCounters, DWORD cb)
{
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return FALSE;
}

BOOL QueryWorkingSet(HANDLE process, LPVOID buffer, DWORD size)
{
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return FALSE;
}

BOOL QueryWorkingSetEx(HANDLE process, LPVOID buffer, DWORD size)
{
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return FALSE;
}

BOOL InitializeProcessForWsWatch(HANDLE hProcess)
{
	return TRUE;
}

BOOL EnumPageFilesA(PVOID callback, LPVOID context)
{
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return FALSE;
}

BOOL EnumPageFilesW(PVOID callback, LPVOID context)
{
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return FALSE;
}

BOOL EmptyWorkingSet(HANDLE hProcess)
{
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return FALSE;
}
