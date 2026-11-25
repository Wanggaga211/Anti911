#pragma once
#include <fltKernel.h>
#include "Common.h"
#include  "IoControlRoutine.h"

typedef struct _MODULE_INFORMATION_
{
	ULONG_PTR ModuleBase;
	ULONG SizeOfImage;
	WCHAR ModulePath[MAX_PATH];
}MODULE_INFORMATION, * PMODULE_INFORMATION;

typedef struct _MODULES_INFORMATION_
{
	ULONG NumberOfModule;
	MODULE_INFORMATION ModuleInfo[1];
}MODULES_INFORMATION, * PMODULES_INFORMATION;

typedef struct _COMMUNICATE_PROCESS_MODULE_
{
	OPERATE_TYPE OperateType;

	ULONG_PTR ProcessIdentity;
	union {

		struct {
			ULONG_PTR ModuleBase;
			ULONG SizeOfImage;
		}Dump;

		struct {
			ULONG_PTR ModuleBase;
			ULONG_PTR LdrpHashTable;
		}Unload;

	}u1;

}COMMUNICATE_PROCESS_MODULE, * PCOMMUNICATE_PROCESS_MODULE;



NTSTATUS PsEnumProcessModules(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);
NTSTATUS PsDumpProcessModule(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);
NTSTATUS PsUnloadProcessModule(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);
NTSTATUS EnumProcessModulesByPeb(PEPROCESS EProcess, PMODULES_INFORMATION ModulesInfo, ULONG NumberOfModule);
NTSTATUS RemoveProcessModuleInPeb(PEPROCESS EProcess, ULONG_PTR ModuleBase);
void WalkerModuleList1(PLIST_ENTRY ListEntry, ULONG EnumType, PMODULES_INFORMATION ModulesInfo, ULONG NumberOfModule);
VOID WalkerModuleList2(PLIST_ENTRY ListEntry, ULONG EnumType, ULONG_PTR ModuleBase);
NTSTATUS SafeCopyProcessModule(PEPROCESS EProcess, ULONG_PTR ModuleBase, ULONG SizeOfImage, PVOID OutputBuffer);
BOOLEAN IsModuleInList(ULONG_PTR ModuleBase, ULONG SizeOfImage, PMODULES_INFORMATION ModulesInfo, ULONG NumberOfModule);