#pragma once

#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)