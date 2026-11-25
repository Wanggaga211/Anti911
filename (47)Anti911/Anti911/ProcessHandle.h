#pragma once
#include <Windows.h>
#include <tchar.h>
#include <iostream>
#include <vector>
#include "IoControl.h"
using namespace std;
typedef struct _HANDLE_INFORMATION_
{
	ULONG_PTR Handle;
	ULONG_PTR Object;
	ULONG ReferenceCount;
	WCHAR ObjectName[MAX_PATH];
	WCHAR HandleName[MAX_PATH];
}HANDLE_INFORMATION, * PHANDLE_INFORMATION;

typedef struct _HANDLES_INFORMATION_
{
	ULONG NumberOfHandle;
	HANDLE_INFORMATION HandleInfo[1];
}HANDLES_INFORMATION, * PHANDLES_INFORMATION;

typedef struct _COMMUNICATE_PROCESS_HANDLE_
{
	OPERATE_TYPE OperateType;

	ULONG_PTR ProcessIdentity;

	union {

		struct {
			ULONG_PTR Handle;
			ULONG_PTR Object;
			ULONG IsForceKill;
		} Close;

	} u1;

}COMMUNICATE_PROCESS_HANDLE, * PCOMMUNICATE_PROCESS_HANDLE;


BOOL EnumProcessHandlesInternal(ULONG_PTR ProcessIdentity, vector<HANDLE_INFORMATION>& HandleInfo);