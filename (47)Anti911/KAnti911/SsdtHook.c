#include "SsdtHook.h"
#include "SystemHelper.h"
#include "MemoryHelper.h"


BOOLEAN SsdtHook(HOOKS* Hooks, char* ServiceName, ULONG_PTR FakeAddress, ULONG ParameterCount)
{

	NTSTATUS  Status = STATUS_UNSUCCESSFUL;
	int i = 0;
	int j = 0;
	BOOLEAN		IsAlreadyHook = FALSE;
	HOOKS* v1 = (HOOKS*)Hooks;
	ULONG32   v3 = NULL;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE   SystemServiceDescriptorTable = NULL;
	ULONG32 ServiceIndex = 0;

	PMDL Mdl = NULL;
	PVOID  VirtualAddress = NULL;
	if (NULL == v1)
	{
		return;
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
				break;    //在数据结构中获取一个位置
			}
		}
		if (i == v1->MaxHooks)
		{
			return IsAlreadyHook;  //没有内存空间提供给新的Hook
		}
	}

	SystemServiceDescriptorTable = GetKeServiceDescriptorTable();

	if (!GetNtXXXServcieIndex(ServiceName, &ServiceIndex))
	{
		return;
	}
	;
	Status = VirtualProtect(&Mdl, SystemServiceDescriptorTable->ServiceTableBase,
		SystemServiceDescriptorTable->NumberOfServices * 4, &VirtualAddress);


#ifdef _WIN64
	CHAR   Bits[4] = { 0 };
	char   v10;
	v3 = (ULONG32)((ULONG64)FakeAddress - (ULONG64)SystemServiceDescriptorTable->ServiceTableBase);
	v3 = v3 << 4;
	if (ParameterCount > 4)
	{
		ParameterCount = ParameterCount - 4;     //NtReadFile  9个参数
	}
	else
	{
		ParameterCount = 0;
	}


	memcpy(&v10, &v3, 1);
	//处理低四位，填写参数个数   如果一个函数的参数为5 那么dwTemp的低4位就是 0001  如果参数是6 就是0002 因为 6要减4 

#define SETBIT(x,y) x|=(1<<y)         //将X的第Y位置1
#define CLRBIT(x,y) x&=~(1<<y)        //将X的第Y位清0
#define GETBIT(x,y) (x & (1 << y))    //取X的第Y位，返回0或非0

	for (j = 0;j < 4;j++)    //一个16进制 4个二进制      0000
	{
		Bits[j] = GETBIT(ParameterCount, j);
		if (Bits[j])
		{
			SETBIT(v10, j);
		}
		else
		{
			CLRBIT(v10, j);
		}
	}

	/*
	ulParamCount    i        szBits[i]    b       i       b
	0101            0         1          0000     0      0001   set
	0101            1         0          0001     1      0001   clr
	0101            2         1          0001     2      0101   set
	0101            3         0          0101     3      0101   clr

	*/
	memcpy(&v3, &v10, 1);
	v1->HookEntry[i].u1.OriginalOffset = InterlockedExchange((PULONG32) & ((PULONG32)VirtualAddress)[ServiceIndex], v3);
#else

	v1->HookEntry[i].u1.OriginalOffset = InterlockedExchange((PULONG32)&((PULONG32)VirtualAddress)[ServiceIndex], FakeAddress);
#endif // 
	UnvirtualProtect(Mdl, VirtualAddress);

	memcpy(v1->HookEntry[i].ServiceName, ServiceName, strlen(ServiceName));
	IsAlreadyHook = TRUE;
	v1->HookEntry[i].ServiceIndex = ServiceIndex;
	v1->HookEntry[i].FakeAddress = FakeAddress;
	v1->HookEntry[i].IsInlineHook = FALSE;
	v1->HookEntry[i].IsAlreadyHook = IsAlreadyHook;
	return IsAlreadyHook;
}

BOOLEAN UnssdtHook(HOOKS* Hooks, char* ServiceName)
{
	HOOK_ENREY* v1 = NULL;
	PMDL Mdl = NULL;
	PVOID  VirtualAddress = NULL;
	ULONG i;
	NTSTATUS  Status = STATUS_UNSUCCESSFUL;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE   SystemServiceDescriptorTable = NULL;
#ifdef _WIN64
#else
	v1 = GetAlreadyHookEntry(Hooks, ServiceName);
	if (v1->IsAlreadyHook)
	{
		//针对SsdtHook
		SystemServiceDescriptorTable = GetKeServiceDescriptorTable();
		Status = VirtualProtect(&Mdl, SystemServiceDescriptorTable->ServiceTableBase,
			SystemServiceDescriptorTable->NumberOfServices * 4, &VirtualAddress);
		InterlockedExchange((PULONG32)&((PULONG32)VirtualAddress)[v1->ServiceIndex],
			v1->u1.OriginalOffset);

		UnvirtualProtect(Mdl, VirtualAddress);

		v1->IsAlreadyHook = FALSE;
	}
#endif
}