#pragma once
#include <fltKernel.h>




#define AllocatePoolWithTag(_POOL_TYPE,ViewSize)          ExAllocatePoolWithTag(_POOL_TYPE, ViewSize, '00xE')    
#define FreePoolWithTag(VirtualAddress)                   ExFreePoolWithTag(VirtualAddress, '00xE')

void InitializeMemroySource();

BOOLEAN
MapFileInKernelSpace(WCHAR* FullPath,
	PVOID* VirtualAddress, PSIZE_T ViewSize);


NTSTATUS VirtualProtect(PMDL* Mdl, PVOID VirtualAddress1, PSIZE_T ViewSize, PVOID* VirtualAddress2);
NTSTATUS UnvirtualProtect(PMDL Mdl, PVOID VirtualAddress2);


NTSTATUS SafeCopyMemoryR32R0(ULONG_PTR Source, ULONG_PTR Destination, ULONG ViewSize);
NTSTATUS SafeCopyMemoryR02R3(PVOID Source, PVOID Destination, ULONG SizeOfImage);



typedef
NTSTATUS
(*LPFN_NTUNMAPVIEWOFSECTION) (
	__in HANDLE ProcessHandle,
	__in PVOID BaseAddress
	);
typedef
NTSTATUS
(*LPFN_NTQUERYVIRTUALMEMORY)(
	__in HANDLE ProcessHandle,
	__in PVOID BaseAddress,
	__in MEMORY_INFORMATION_CLASS MemoryInformationClass,
	__out_bcount(MemoryInformationLength) PVOID MemoryInformation,
	__in SIZE_T MemoryInformationLength,
	__out_opt PSIZE_T ReturnLength
	);
typedef
NTSTATUS
(*LPFN_NTPROTECTVIRTUALMEMORY)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);
extern LPFN_NTUNMAPVIEWOFSECTION __NtUnmapViewOfSection;
extern LPFN_NTQUERYVIRTUALMEMORY __NtQueryVirtualMemory;
extern LPFN_NTPROTECTVIRTUALMEMORY  __NtProtectVirtualMemory;