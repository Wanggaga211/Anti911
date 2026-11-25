#include "InlineHook.h"
#include "SystemHelper.h"
#include "MemoryHelper.h"
BOOLEAN InlineHook(HOOKS* Hooks, char* ServiceName, ULONG_PTR FakeAddress)
{

	int i = 0;
	int j = 0;
	BOOLEAN		IsAlreadyHook = FALSE;

	HOOKS* v1 = (HOOKS*)Hooks;

	ULONG32   v2 = NULL;
	ULONG_PTR OriginalAddress = 0;

	if (NULL == v1)
	{
		return;
	}

	PSYSTEM_SERVICE_DESCRIPTOR_TABLE   SystemServiceDescriptorTable = GetKeServiceDescriptorTable();

	/*
	fffff880`045996f8  fffff800`040b0940 00000000`00000000
	fffff880`04599708  00000000`00000000 fffffa80`615073b0

	*/

	ULONG32 ServiceIndex = 0;
	NTSTATUS  Status = STATUS_UNSUCCESSFUL;
	PMDL Mdl = NULL;
	PVOID  VirtualAddress = NULL;
	if (!GetNtXXXServcieIndex(ServiceName, &ServiceIndex))
	{


		//不是Ssdt服务函数
		ANSI_STRING v5;
		UNICODE_STRING v6;
		RtlInitAnsiString(&v5, ServiceName);
		RtlAnsiStringToUnicodeString(&v6, &v5, TRUE);
		OriginalAddress = MmGetSystemRoutineAddress(&v6);    //模块导出函数
		RtlFreeUnicodeString(&v6);

	}
	else
	{
		v2 = ((PULONG32)SystemServiceDescriptorTable->ServiceTableBase)[ServiceIndex];   //

#ifdef _WIN64

		v2 = v2 >> 4;
		OriginalAddress = (v2 + (ULONG64)(SystemServiceDescriptorTable->ServiceTableBase));

#else
		OriginalAddress = v2;
#endif

	}

	if (OriginalAddress == NULL)
	{
		return IsAlreadyHook;
	}

	/* 查找是否已被设置了钩子 */
	for (i = 0; i < v1->MaxHooks; i++)
	{

		if (!strcmp(v1->HookEntry[i].ServiceName, ServiceName))
		{
			if (v1->HookEntry[i].IsAlreadyHook == 1)
			{
				IsAlreadyHook = TRUE;
				return IsAlreadyHook;
			}
		}
	}
	/* 如果没有设置源函数的钩子函数，在表中找出一个可供记录的位置. */
	if (i == v1->MaxHooks)
	{
		for (i = 0; i < v1->MaxHooks; i++)
		{
			if (v1->HookEntry[i].IsAlreadyHook == 0)
			{
				break;
			}
		}
		if (i == v1->MaxHooks)
		{
			return IsAlreadyHook;
		}
	}


	Status = VirtualProtect(&Mdl, OriginalAddress,
		0x1000, &VirtualAddress);

	/*
	kd> u fffff800`03e78bc0
	nt!KeBugCheckEx:
	fffff800`03e78bc0 48894c2408      mov     qword ptr [rsp+8],rcx
	fffff800`03e78bc5 4889542410      mov     qword ptr [rsp+10h],rdx
	fffff800`03e78bca 4c89442418      mov     qword ptr [rsp+18h],r8
	fffff800`03e78bcf 4c894c2420      mov     qword ptr [rsp+20h],r9
	fffff800`03e78bd4 9c              pushfq
	fffff800`03e78bd5 4883ec30        sub     rsp,30h
	fffff800`03e78bd9 fa              cli

	*/

	v1->HookEntry[i].FakeAddress = FakeAddress;
#ifdef _WIN64
	/*
	v1->HookEntry[i].CodeLength = 14;
	UCHAR    PatchCodeData[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";   //InlineHook  Jmp 函数地址
	memcpy(v1->HookEntry[i].OriginalCode, (PVOID)VirtualAddress, v1->HookEntry[i].CodeLength);   //保存原先函数的指令
	memcpy(PatchCodeData + 6, &(v1->HookEntry[i].FakeAddress), 8);
	memcpy((PVOID)VirtualAddress, PatchCodeData, v1->HookEntry[i].CodeLength);
	*/



	//保存源函数14个字节指令长 构建跳床
	v1->HookEntry[i].CodeLength = 14;
	memcpy(v1->HookEntry[i].Trampoline, (PVOID)VirtualAddress, v1->HookEntry[i].CodeLength);
	//源函数14个字节之后的内容所在的地址
	ULONG_PTR v3 = (PUINT8)OriginalAddress + v1->HookEntry[i].CodeLength;
	//构建跳转到该地址的Shell
	UCHAR v4[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";  //Jmp Old+14
	memcpy(v4 + 6, &v3, 8);
	memcpy(v1->HookEntry[i].Trampoline + v1->HookEntry[i].CodeLength, v4, v1->HookEntry[i].CodeLength);

	//覆盖源函数指令跳转至Fake函数
	UCHAR    PatchCodeData[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";   //InlineHook  Jmp 函数地址
	memcpy(v1->HookEntry[i].OriginalCode, (PVOID)VirtualAddress, v1->HookEntry[i].CodeLength);   //保存原先函数的指令
	memcpy(PatchCodeData + 6, &(v1->HookEntry[i].FakeAddress), 8);
	memcpy((PVOID)VirtualAddress, PatchCodeData, v1->HookEntry[i].CodeLength);



#else
	/*
	v1->HookEntry[i].CodeLength = 5;
	UCHAR    PatchCodeData[] = "\xe9\x00\x00\x00\x00";   //InlineHook  Jmp 函数地址
	memcpy(v1->HookEntry[i].OriginalCode, (PVOID)VirtualAddress, v1->HookEntry[i].CodeLength);   //保存原先函数的指令
	*((ULONG*)&PatchCodeData[1]) = (PUCHAR)v1->HookEntry[i].FakeAddress - ((PUCHAR)OriginalAddress + 5);
	memcpy((PVOID)VirtualAddress, PatchCodeData, v1->HookEntry[i].CodeLength);
	*/



	//保存源函数5个字节指令长 构建跳床
	v1->HookEntry[i].CodeLength = 5;
	memcpy(v1->HookEntry[i].Trampoline, (PVOID)VirtualAddress, v1->HookEntry[i].CodeLength);
	//源函数5个字节之后的内容所在的地址
	ULONG_PTR v3 = (PUINT8)OriginalAddress + v1->HookEntry[i].CodeLength;
	UCHAR v4[] = "\xe9\x00\x00\x00\x00";
	*((ULONG*)&v4[1]) = (PUCHAR)v3 - (v1->HookEntry[i].Trampoline + 5 + 5);
	memcpy(v1->HookEntry[i].Trampoline + v1->HookEntry[i].CodeLength, v4, v1->HookEntry[i].CodeLength);

	UCHAR    PatchCodeData[] = "\xe9\x00\x00\x00\x00";   //InlineHook  Jmp 函数地址
	memcpy(v1->HookEntry[i].OriginalCode, (PVOID)VirtualAddress, v1->HookEntry[i].CodeLength);   //保存原先函数的指令
	*((ULONG*)&PatchCodeData[1]) = (PUCHAR)v1->HookEntry[i].FakeAddress - ((PUCHAR)OriginalAddress + 5);
	memcpy((PVOID)VirtualAddress, PatchCodeData, v1->HookEntry[i].CodeLength);

	/*
	nt!NtTerminateProcess:
	84a97d9a 8bff            mov     edi,edi
	84a97d9c 55              push    ebp
	84a97d9d 8bec            mov     ebp,esp
	84a97d9f 83ec10          sub     esp,10h
	84a97da2 53              push    ebx
	84a97da3 56              push    esi
	84a97da4 648b3524010000  mov     esi,dword ptr fs:[124h]
	84a97dab 8b5e50          mov     ebx,dword ptr [esi+50h]
	2: kd> g
	Breakpoint 1 hit
	KAnti911!InlineHook+0x3a8:
	9e40ca78 8a45e7          mov     al,byte ptr [ebp-19h]
	2: kd> u 0x88f0a024
	ReadVirtual: 88f0a024 not properly sign extended
	88f0a024 8bff            mov     edi,edi
	88f0a026 55              push    ebp
	88f0a027 8bec            mov     ebp,esp
	88f0a029 e971ddb8fb      jmp     nt!NtTerminateProcess+0x5 (84a97d9f)
	*/

#endif

	UnvirtualProtect(Mdl, VirtualAddress);
	IsAlreadyHook = TRUE;
	memcpy(v1->HookEntry[i].ServiceName, ServiceName, strlen(ServiceName));
	v1->HookEntry[i].u1.OriginalAddress = OriginalAddress;

	v1->HookEntry[i].IsAlreadyHook = TRUE;
	v1->HookEntry[i].IsInlineHook = TRUE;
	return IsAlreadyHook;
}