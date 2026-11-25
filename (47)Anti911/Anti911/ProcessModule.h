#pragma once
#include <Windows.h>
#include <tchar.h>
#include <iostream>
#include <vector>
#include "IoControl.h"
using namespace std;


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


void ProcessModuleInfo();
BOOL EnumProcessModules(ULONG_PTR ProcessIdentity, vector<MODULE_INFORMATION>& ModuleInfo);
void DumpProcessModule(ULONG_PTR ProcessIdentity, ULONG_PTR ModuleBase, ULONG SizeOfImage);
BOOL UnloadProcessModule(ULONG_PTR ProcessIdentity, ULONG_PTR ModuleBase);
