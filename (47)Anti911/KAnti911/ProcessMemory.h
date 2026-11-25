#pragma once
#include <fltKernel.h>
#include "IoControlRoutine.h"

#define MAX_LENGTH 20

typedef struct _MEMORY_INFORMATION_
{
	PVOID     BaseAddress;
	SIZE_T    RegionSize;
	ULONG     Protect;
	ULONG     State;
	ULONG     Type;
}MEMORY_INFORMATION, *PMEMORY_INFORMATION;

typedef struct _MEMORYS_INFORMATION_
{
	ULONG NumberOfMemory;
	MEMORY_INFORMATION MemoryInfo[1];
}MEMORYS_INFORMATION, * PMEMORYS_INFORMATION;


typedef struct _COMMUNICATE_PROCESS_MEMORY_
{
	OPERATE_TYPE OperateType;

	union {
		struct {
			ULONG_PTR ProcessIdentity;
		} Query;

		struct
		{
			PVOID      BaseAddress;
			SIZE_T     RegionSize;
			ULONG_PTR      ProcessIdentity;
		}Read;
		struct
		{
			PVOID      BaseAddress;
			SIZE_T     RegionSize;
			ULONG_PTR      ProcessIdentity;
			char* BufferData;
		}Write;
		struct
		{
			ULONG_PTR       ProcessIdentity;
			PVOID       BaseAddress;
			SIZE_T      RegionSize;
			ULONG       NewProtect;
			ULONG       OldProtect;
		}Modify;
	} u1;
}COMMUNICATE_PROCESS_MEMORY, * PCOMMUNICATE_PROCESS_MEMORY;

NTSTATUS PsEnumProcessMemorys(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);
NTSTATUS EnumProcessMemorys(PEPROCESS EProcess, PMEMORYS_INFORMATION MemorysInfo, ULONG NumberOfMemory);
NTSTATUS PsReadProcessMemory(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);
NTSTATUS PsWriteProcessMemory(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);
NTSTATUS PsModifyProcessMemory(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);