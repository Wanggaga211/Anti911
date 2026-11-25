#pragma once
#include <Windows.h>
#include <iostream>
#include <tchar.h>
#include "IoControl.h"
using namespace std;

typedef struct _COMMUNICATE_APC_INJECT_
{
	OPERATE_TYPE OperateType;

	ULONG_PTR ProcessIdentity;
	WCHAR  DllPath[MAX_PATH];

}COMMUNICATE_APC_INJECT, * PCOMMUNICATE_APC_INJECT;

BOOL ApcInject();