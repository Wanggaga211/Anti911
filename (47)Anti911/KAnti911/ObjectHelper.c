#include "ObjectHelper.h"
#include "SystemHelper.h"

LPFN_OBGETOBJECTTYPE __ObGetObjectType = NULL;
LPFN_NTQUERYOBJECT   __NtQueryObject = NULL;
LPFN_NTCLOSE         __NtClose = NULL;
void InitializeObjectSource()
{
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE   SystemServiceDescriptorTable = NULL;
	ULONG32 ServiceIndex = 0;
	if (__ObGetObjectType == NULL)
	{
		UNICODE_STRING v1;
		RtlInitUnicodeString(&v1, L"ObGetObjectType");
		__ObGetObjectType = (LPFN_OBGETOBJECTTYPE)MmGetSystemRoutineAddress(&v1);   //系统第一个模块的导出表中获得
	}


	if (__NtQueryObject == NULL)
	{
		
		SystemServiceDescriptorTable = GetKeServiceDescriptorTable();
		if (!GetNtXXXServcieIndex("NtQueryObject", &ServiceIndex))
		{
			return;
		}
		if (!NT_SUCCESS(GetNtXXXServcieAddress(ServiceIndex, &__NtQueryObject)))
		{
			return;
		}
	}

	if (__NtClose == NULL)
	{
		SystemServiceDescriptorTable = GetKeServiceDescriptorTable();
		if (!GetNtXXXServcieIndex("NtClose", &ServiceIndex))
		{
			return;
		}
		if (!NT_SUCCESS(GetNtXXXServcieAddress(ServiceIndex, &__NtClose)))
		{
			return;
		}
	}

}