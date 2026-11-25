#include "HookHelper.h"
#include "MemoryHelper.h"
#include "SystemHelper.h"
#include "FakeService.h"
#include "SsdtHook.h"
#include "InlineHook.h"
#include "KiFastCall.h"
#include "Common.h"

HOOKS* __Hooks = NULL;
PVOID __FakeNtoskrnl = NULL;
HOOKS* InitializeHookSource(ULONG MaxHooks)
{
	HOOKS* Hooks = (HOOKS*)AllocatePoolWithTag(NonPagedPool, sizeof(HOOKS));
	if (Hooks)
	{
		Hooks->MaxHooks = MaxHooks;
		Hooks->HookEntry = (HOOK_ENREY*)ExAllocatePool(NonPagedPool, sizeof(HOOK_ENREY) * MaxHooks);
		if (NULL != Hooks->HookEntry)
		{
			memset(Hooks->HookEntry, 0, sizeof(HOOK_ENREY) * MaxHooks);
			return Hooks;
		}
		FreePoolWithTag(Hooks);
	}

	return NULL;
}
HOOK_ENREY* GetAlreadyHookEntry(HOOKS* Hooks, char* ServiceName)
{
	HOOKS* v1 = (HOOKS*)Hooks;
	int i = 0;
	for (i = 0; i < v1->MaxHooks; i++)
	{

		if (!strcmp(v1->HookEntry[i].ServiceName, ServiceName))
		{
			if (v1->HookEntry[i].IsAlreadyHook == 1)
			{

				return &v1->HookEntry[i];
			}
		}
	}
	if (i == v1->MaxHooks)
	{
		return NULL;
	}
}
void InstallSsdtHook()
{
#ifdef _WIN64
	//InlineHook(__Hooks,"KeBugCheckEx", FakeTerminateProcess);
	//SsdtHook(__Hooks, "ZwTerminateProcess", KeBugCheckEx, 5);
#else
	//SsdtHook(__Hooks, "ZwTerminateProcess", FakeTerminateProcess, 2);
#endif
}

void InstallInlineHook()
{
#ifdef _WIN64
	InlineHook(__Hooks, "ZwTerminateProcess", FakeTerminateProcess);

#else
	InlineHook(__Hooks, "ZwTerminateProcess", FakeTerminateProcess);
#endif


}

void InstallKiFastCallHook()
{
#ifdef _WIN64
	

#else
	GetKeServiceDescriptorTable();
	KiFastCallHook(__Hooks,&__FakeNtoskrnl);
#endif
}


void UninitializeHookSource(HOOKS* Hooks)
{
	PMDL Mdl = NULL;
	PVOID  VirtualAddress = NULL;
	ULONG i;
	HOOKS* v1 = NULL;
	NTSTATUS  Status = STATUS_UNSUCCESSFUL;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE   SystemServiceDescriptorTable = NULL;
	if (NULL != Hooks)
	{
		v1 = (HOOKS*)Hooks;
		for (i = 0; i < v1->MaxHooks; i++)
		{
			if (v1->HookEntry[i].IsAlreadyHook)
			{

				if (v1->HookEntry[i].IsInlineHook)
				{
					Status = VirtualProtect(&Mdl, v1->HookEntry[i].u1.OriginalAddress,
						v1->HookEntry[i].CodeLength, &VirtualAddress);

					memcpy((PVOID)VirtualAddress, v1->HookEntry[i].OriginalCode, v1->HookEntry[i].CodeLength);

					UnvirtualProtect(Mdl, VirtualAddress);
				}
				else if (v1->HookEntry[i].IsKiFastCallHook)
				{

					/*
					KIRQL Irql;
					Irql = KeRaiseIrqlToDpcLevel();

					CloseWriteProtect();
					memcpy((PVOID)v1->HookEntry[i].u1.OriginalAddress, v1->HookEntry[i].OriginalCode, v1->HookEntry[i].CodeLength);
			
					OpenWriteProtect();
					KeLowerIrql(Irql);*/


					Status = VirtualProtect(&Mdl, v1->HookEntry[i].u1.OriginalAddress,
						v1->HookEntry[i].CodeLength, &VirtualAddress);

					memcpy((PVOID)VirtualAddress, v1->HookEntry[i].OriginalCode, v1->HookEntry[i].CodeLength);

					UnvirtualProtect(Mdl, VirtualAddress);


				}
				else
				{

					SystemServiceDescriptorTable = GetKeServiceDescriptorTable();
					Status = VirtualProtect(&Mdl, SystemServiceDescriptorTable->ServiceTableBase,
						SystemServiceDescriptorTable->NumberOfServices * 4, &VirtualAddress);
					InterlockedExchange((PULONG32) & ((PULONG32)VirtualAddress)[v1->HookEntry[i].ServiceIndex],
						v1->HookEntry[i].u1.OriginalOffset);

					UnvirtualProtect(Mdl, VirtualAddress);

				}

				v1->HookEntry[i].IsAlreadyHook = FALSE;
			}
		}
		FreePoolWithTag(v1->HookEntry);
		FreePoolWithTag(v1);
	}



	//KiFastCall×ÊÔ´
	if (__FakeNtoskrnl != NULL)
	{
		FreePoolWithTag(__FakeNtoskrnl);

		__FakeNtoskrnl = NULL;
	}
	return;
}