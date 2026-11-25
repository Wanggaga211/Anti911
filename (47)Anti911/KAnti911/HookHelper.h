#pragma once
#include <fltKernel.h>
typedef struct _HOOK_ENREY_
{

	BOOLEAN     IsAlreadyHook;
	BOOLEAN		IsInlineHook;
	BOOLEAN     IsKiFastCallHook;
	char        ServiceName[20];
	ULONG       ServiceIndex;
	union
	{
		ULONG_PTR   OriginalAddress;
		ULONG32     OriginalOffset;
	}u1;
	ULONG_PTR	FakeAddress;
	PUCHAR      Trampoline[32];
	PUCHAR	    OriginalCode[32];
	ULONG       CodeLength;
}HOOK_ENREY;

typedef struct _HOOKS_ {
	HOOK_ENREY* HookEntry;    //ÏßÐÔ±í
	ULONG		MaxHooks;
}HOOKS;

HOOKS* InitializeHookSource(ULONG MaxHooks);
void UninitializeHookSource(HOOKS* Hooks);
HOOK_ENREY* GetAlreadyHookEntry(HOOKS* Hooks, char* ServiceName);
void InstallSsdtHook();
void InstallInlineHook();
void InstallKiFastCallHook();
extern HOOKS* __Hooks;




