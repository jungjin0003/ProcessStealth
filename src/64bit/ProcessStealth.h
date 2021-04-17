#pragma once

#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

DWORD GetProcessIdByImageName(wchar_t* ProcessName);
BOOL ProcessStealth(wchar_t *TargetProcessName, wchar_t *HideProcessName);

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define Upper(s1) s1 >= 65 && s1 <= 90 ? (wchar_t)s1 + 32 : s1

#define NewNtQuerySystemInformation_Size (ULONGLONG)AtherFunc - (ULONGLONG)NewNtQuerySystemInformation