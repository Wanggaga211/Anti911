#pragma once
#include "FakeService.h"
#include "HookHelper.h"
#include "SystemHelper.h"
#include "KiFastCall.h"
#include "Common.h"


LPFN_NTSETEVENT __OriginalSetEvent = NULL;
PUCHAR	__KiFastCallEntryRetAddress = 0;
ULONG_PTR __stdcall FilterService(ULONG_PTR ServiceTableBase, ULONG ServiceIndex, ULONG_PTR ServiceAddress)
{
	
	if (ServiceTableBase == (ULONG_PTR)__SystemServiceDescriptorTable->ServiceTableBase)
	{
		return __FakeKeServiceDescriptorTable.ServiceTableBase[ServiceIndex];    //没有进行Fake   
	}
	return ServiceAddress;
}
NTSTATUS
NTAPI
FakeTerminateProcess(
	_In_opt_ HANDLE ProcessHandle,
	_In_ NTSTATUS ExitStatus)
{

	int i = 0;
	HOOKS* v1 = (HOOKS*)__Hooks;
	for (i = 0; i < v1->MaxHooks; i++)
	{

		if (strcmp(v1->HookEntry[i].ServiceName, "ZwTerminateProcess")==0)
		{	

			return ((LPFN_TERMINATEPROCESS)(v1->HookEntry[i].Trampoline))(ProcessHandle, ExitStatus);
			
		}
	}

	return STATUS_UNSUCCESSFUL;
}


#ifdef _WIN64
#else
NTSTATUS NTAPI FakeSetEvent(IN PHANDLE EventHandle, OUT PLONG PreviousState OPTIONAL)  //系统的传参
{


	if (*EventHandle != (HANDLE)0x12345678 || ExGetPreviousMode() != KernelMode)
	{

		__OriginalSetEvent(EventHandle, PreviousState);  //调用原始函数
	}
	else
	{

		__asm
		{

			//栈回溯获取KiFastCallEntryRetAddres地址
			mov eax, dword ptr[ebp + 4]  // 取出主调函数的IP指令
			mov __KiFastCallEntryRetAddress, eax


			/*
			848798c6 f6456c01        test    byte ptr [ebp+6Ch],1
			848798ca 7434            je      nt!KiSystemServicePostCall+0x3a (84879900)

			*/

		}

	}

	return STATUS_SUCCESS;

}
#endif // _WIN64




