#include "ProcessHandle.h"
#include "ProcessHelper.h"
#include "SystemHelper.h"
#include "ProcessThread.h"
#include "MemoryHelper.h"
#include "ObjectHelper.h"
#include "StringHelper.h"


int __ObjectCount = 0;   //记录句柄值
NTSTATUS  EnumProcessHandlesByHandleTable(HANDLE ProcessIdentify, PEPROCESS EProcess, PHANDLES_INFORMATION HandlesInfo, ULONG NumberOfHandle)
{
	PHANDLE_TABLE HandleTable = NULL;
	ULONG_PTR     TableCode = 0;
	ULONG         Flag = 0;
	NTSTATUS      Status = STATUS_SUCCESS;
	ULONG_PTR     ObjectCount = 0;
	__ObjectCount = 1;
	__try
	{
		{
			HandleTable = (PHANDLE_TABLE)(*((ULONG_PTR*)((ULONG_PTR)EProcess + _HANDLE_TABLE_)));
			if (MmIsAddressValid(HandleTable))
			{
				TableCode = (ULONG_PTR)(HandleTable->TableCode) & 0xFFFFFFFFFFFFFFFC; //8421
				Flag = (ULONG)(HandleTable->TableCode) & 0x03;

				switch (Flag)
				{
				case 0:
				{
					Status = HandleTable0(TableCode, EProcess, HandlesInfo, NumberOfHandle);
					break;
				}
				case 1:
				{
					Status = HandleTable1(TableCode, EProcess, HandlesInfo, NumberOfHandle);

					/*
					kd> dq 0xfffff8a0`0167c000
					fffff8a0`0167c000  fffff8a0`0132a000 fffff8a0`0167d000
					fffff8a0`0167c010  fffff8a0`01499000 fffff8a0`0157e000
					fffff8a0`0167c020  fffff8a0`01946000 00000000`00000000

					*/


					break;
				}
				case 2:
				{
					Status  = HandleTable2(TableCode, EProcess, HandlesInfo, NumberOfHandle);
					break;
				}
				case 3:
				{
					Status = HandleTable3(TableCode, EProcess, HandlesInfo, NumberOfHandle);
					break;
				}
				}
			}
			else
			{
				Status = STATUS_UNSUCCESSFUL;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	return Status;
}
NTSTATUS HandleTable0(ULONG_PTR TableCode, PEPROCESS EProcess, PHANDLES_INFORMATION HandlesInfo, ULONG NumberOfHandle)
{
	PHANDLE_TABLE_ENTRY HandleTableEntry = NULL;
	ULONG Index = 0;
	NTSTATUS Status;

	HandleTableEntry = (PHANDLE_TABLE_ENTRY)((ULONG_PTR*)(TableCode + _OFFSET_));

	/*
	kd> dq fffff8a0`0132a000
	fffff8a0`0132a000  00000000`00000000 000ca000`fffffffe
	fffff8a0`0132a010  fffff8a0`013395e1 00000000`00000009
	fffff8a0`0132a020  fffff8a0`07461e81 00000000`00000003

	*/


	ULONG_PTR  ObjectCount = 0;

	for (Index = 1;Index <= (PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY)); Index++)
	{
		if (MmIsAddressValid((PVOID)HandleTableEntry))
		{

			PVOID ObjectHeader = (PVOID)(*(ULONG_PTR*)HandleTableEntry & 0xFFFFFFFFFFFFFFF8);

			/*
			kd> dt _Object_header  fffff8a0`013395e0
			nt!_OBJECT_HEADER
			   +0x000 PointerCount     : 0n1
			   +0x008 HandleCount      : 0n1
			   +0x008 NextToFree       : 0x00000000`00000001 Void
			   +0x010 Lock             : _EX_PUSH_LOCK
			   +0x018 TypeIndex        : 0x23 '#'
			   +0x019 TraceFlags       : 0 ''
			   +0x01a InfoMask         : 0x8 ''
			   +0x01b Flags            : 0 ''
			   +0x020 ObjectCreateInfo : 0xfffffa80`625c1d80 _OBJECT_CREATE_INFORMATION
			   +0x020 QuotaBlockCharged : 0xfffffa80`625c1d80 Void
			   +0x028 SecurityDescriptor : (null) 
			   +0x030 Body             : _QUAD		
			*/

			if (MmIsAddressValid(ObjectHeader))
			{
				PVOID ObjectBody = (PVOID)((ULONG_PTR)ObjectHeader + _OBJECT_BODY_);


				if (MmIsAddressValid(ObjectBody))   //这里应当判断对象是否合法
				{
					DbgPrint("ObjectBody:%p\r\n", ObjectBody);
					

					if (NumberOfHandle > HandlesInfo->NumberOfHandle)
					{
						InsertHandleToList((PEPROCESS)EProcess,
							(HANDLE)(__ObjectCount*sizeof(int)),
							(ULONG_PTR)ObjectBody,
							HandlesInfo);
						__ObjectCount++;
					}
					HandlesInfo->NumberOfHandle++;
				
				}
			}
		}
		HandleTableEntry++;     //结构体指针++ 一加一个结构体

	}


	if (NumberOfHandle >= HandlesInfo->NumberOfHandle)
	{
		Status = STATUS_SUCCESS;
	}
	else
	{
		Status = STATUS_BUFFER_TOO_SMALL;
	}
	return Status;
}
NTSTATUS HandleTable1(ULONG_PTR TableCode, PEPROCESS EProcess, PHANDLES_INFORMATION HandlesInfo, ULONG NumberOfHandle)
{
	NTSTATUS Status = STATUS_SUCCESS;
	do
	{
		Status = HandleTable0(*(ULONG_PTR*)TableCode, EProcess, HandlesInfo, NumberOfHandle);
		TableCode += sizeof(ULONG_PTR);
	} while (*(PULONG_PTR)TableCode != 0 && MmIsAddressValid((PVOID) * (PULONG_PTR)TableCode));

	return Status;
}
NTSTATUS  HandleTable2(ULONG_PTR TableCode, PEPROCESS EProcess, PHANDLES_INFORMATION HandlesInfo, ULONG NumberOfHandle)
{
	NTSTATUS Status = STATUS_SUCCESS;
	do
	{
		Status = HandleTable1(*(ULONG_PTR*)TableCode, EProcess, HandlesInfo, NumberOfHandle);
		TableCode += sizeof(ULONG_PTR);
	} while (*(PULONG_PTR)TableCode != 0);

	return Status;
}
NTSTATUS  HandleTable3(ULONG_PTR TableCode, PEPROCESS EProcess, PHANDLES_INFORMATION HandlesInfo, ULONG NumberOfHandle)
{
	NTSTATUS Status = STATUS_SUCCESS;
	do
	{
		Status = HandleTable2(*(ULONG_PTR*)TableCode, EProcess, HandlesInfo, NumberOfHandle);
		TableCode += sizeof(ULONG_PTR);
	} while (*(PULONG_PTR)TableCode != 0);

	return Status;
}

NTSTATUS PsEnumProcessHandles(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{
	NTSTATUS Status1 = STATUS_UNSUCCESSFUL, Status2 = STATUS_UNSUCCESSFUL;
	PCOMMUNICATE_PROCESS_HANDLE v1 = (PCOMMUNICATE_PROCESS_HANDLE)InputBuffer;
	PEPROCESS EProcess = NULL;
	ULONG_PTR ProcessIdentity = 0;
	ULONG NumberOfHandle = (OutputBufferLength - sizeof(HANDLES_INFORMATION)) / sizeof(HANDLE_INFORMATION);


	if (!InputBuffer ||
		InputBufferLength != sizeof(COMMUNICATE_PROCESS_HANDLE) ||
		!OutputBuffer ||
		OutputBufferLength < sizeof(HANDLES_INFORMATION))
	{
		return STATUS_INVALID_PARAMETER;
	}

	
	ProcessIdentity = v1->ProcessIdentity;

	if (ProcessIdentity)
	{
		Status2 = PsLookupProcessByProcessId((HANDLE)ProcessIdentity, &EProcess);
	
	}

	if (!EProcess)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (PsIsRealProcess(EProcess))
	{
		//Status1 = EnumProcessHandlesByService(ProcessIdentity, EProcess, (PHANDLES_INFORMATION)OutputBuffer, NumberOfHandle);
	
		Status1 = EnumProcessHandlesByHandleTable(ProcessIdentity, EProcess, (PHANDLES_INFORMATION)OutputBuffer, NumberOfHandle);
	
	}

	if (NT_SUCCESS(Status2))
	{
		ObfDereferenceObject(EProcess);
	}

	return Status1;
}
NTSTATUS EnumProcessHandlesByService(ULONG_PTR ProcessIdentity, PEPROCESS EProcess, PHANDLES_INFORMATION HandlesInfo, ULONG NumberOfHandle)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	ULONG v7 = 0x10000;
	PETHREAD EThread = NULL;
	CHAR PreviousMode = 0;



	if (__NtQuerySystemInformation == NULL)
	{
		PSYSTEM_SERVICE_DESCRIPTOR_TABLE   SystemServiceDescriptorTable = NULL;
		ULONG32 ServiceIndex = 0;
		SystemServiceDescriptorTable = GetKeServiceDescriptorTable();
		if (!GetNtXXXServcieIndex("NtQuerySystemInformation", &ServiceIndex))
		{
			return;
		}
		if (!NT_SUCCESS(GetNtXXXServcieAddress(ServiceIndex, &__NtQuerySystemInformation)))
		{
			return;
		}
	}

	EThread = PsGetCurrentThread();
	PreviousMode = ChangePreviousMode(EThread);

	do
	{
		PVOID v5 = AllocatePoolWithTag(PagedPool, v7);
		if (v5)
		{
			memset(v5, 0, v7);
			Status = __NtQuerySystemInformation(SystemHandleInformation, v5, v7, &v7);
			if (NT_SUCCESS(Status))
			{
				PSYSTEM_HANDLE_INFORMATION v1 = (PSYSTEM_HANDLE_INFORMATION)v5;
				ULONG i = 0;
				for (i = 0; i < v1->NumberOfHandle; i++)
				{
					if (ProcessIdentity == v1->Handle[i].UniqueProcessId)
					{
						if (NumberOfHandle > HandlesInfo->NumberOfHandle)
						{
							InsertHandleToList((PEPROCESS)EProcess,
								(HANDLE)v1->Handle[i].HandleValue,
								(ULONG_PTR)v1->Handle[i].Object,
								HandlesInfo);
						}

						HandlesInfo->NumberOfHandle++;
					}
				}
			}

			FreePoolWithTag(v5, 0);
			v7 *= 2;
		}
	} while (Status == STATUS_INFO_LENGTH_MISMATCH);

	RecoverPreviousMode(EThread, PreviousMode);

	if (NT_SUCCESS(Status))
	{
		if (NumberOfHandle >= HandlesInfo->NumberOfHandle)
		{
			Status = STATUS_SUCCESS;
		}
		else
		{
			Status = STATUS_BUFFER_TOO_SMALL;
		}
	}

	return Status;
}
VOID InsertHandleToList(PEPROCESS EProcess, HANDLE HandleValue, ULONG_PTR ObjectValue, PHANDLES_INFORMATION HandlesInfo)
{


	BOOLEAN IsAttach = FALSE;
	KAPC_STATE ApcState;
	PHANDLE_INFORMATION v5 = NULL;
	if (ObjectValue &&
		MmIsAddressValid((PVOID)ObjectValue) &&
		(v5 = (PHANDLE_INFORMATION)AllocatePoolWithTag(NonPagedPool, sizeof(HANDLE_INFORMATION))) != NULL)
	{
		memset(v5, 0, sizeof(HANDLE_INFORMATION));

		if (IoGetCurrentProcess() != EProcess)
		{
			KeStackAttachProcess(EProcess, &ApcState);
			IsAttach = TRUE;
		}

		v5->Handle = HandleValue;
		v5->Object = ObjectValue;

#ifdef _WIN64
		ULONG Offset = 0x30;
		/*
		kd> dt  _object_Header
	nt!_OBJECT_HEADER
	   +0x000 PointerCount     : Int8B
	   +0x008 HandleCount      : Int8B
	   +0x008 NextToFree       : Ptr64 Void
	   +0x010 Lock             : _EX_PUSH_LOCK
	   +0x018 TypeIndex        : UChar
	   +0x019 TraceFlags       : UChar
	   +0x01a InfoMask         : UChar
	   +0x01b Flags            : UChar
	   +0x020 ObjectCreateInfo : Ptr64 _OBJECT_CREATE_INFORMATION
	   +0x020 QuotaBlockCharged : Ptr64 Void
	   +0x028 SecurityDescriptor : Ptr64 Void
	   +0x030 Body             : _QUAD

		*/
#else
		ULONG Offset = 0x18;

		/*
		1: kd> dt _Object_Header
	nt!_OBJECT_HEADER
	   +0x000 PointerCount     : Int4B
	   +0x004 HandleCount      : Int4B
	   +0x004 NextToFree       : Ptr32 Void
	   +0x008 Lock             : _EX_PUSH_LOCK
	   +0x00c TypeIndex        : UChar
	   +0x00d TraceFlags       : UChar
	   +0x00e InfoMask         : UChar
	   +0x00f Flags            : UChar
	   +0x010 ObjectCreateInfo : Ptr32 _OBJECT_CREATE_INFORMATION
	   +0x010 QuotaBlockCharged : Ptr32 Void
	   +0x014 SecurityDescriptor : Ptr32 Void
	   +0x018 Body             : _QUAD

		*/
#endif 

		if (MmIsAddressValid((PVOID)(ObjectValue - Offset)))
		{
			v5->ReferenceCount = *(PULONG_PTR)(ObjectValue - 0x18);
		}
		else
		{
			v5->ReferenceCount = 0;
		}

		ObGetObjectName((HANDLE)HandleValue, ObjectValue, v5->HandleName);
		ObGetTypeName((HANDLE)HandleValue, ObjectValue, v5->ObjectName);

		if (IsAttach)
		{
			KeUnstackDetachProcess(&ApcState);
			IsAttach = FALSE;
		}

		memcpy(&HandlesInfo->HandleInfo[HandlesInfo->NumberOfHandle], v5, sizeof(HANDLE_INFORMATION));
		FreePoolWithTag(v5, 0);
		v5 = NULL;
	}
}
VOID ObGetObjectName(HANDLE HandleValue, ULONG_PTR ObjectValue, WCHAR* ObjectName)
{
	PVOID v5 = NULL;
	PETHREAD EThread = NULL;
	CHAR PreviousMode = 0;
	v5 = AllocatePoolWithTag(PagedPool, 0x1000);



	if (v5)
	{
		ULONG ReturnLength = 0;
	

		memset(v5, 0, 0x1000);


		if (__NtQueryObject == NULL)
		{
			PSYSTEM_SERVICE_DESCRIPTOR_TABLE   SystemServiceDescriptorTable = NULL;
			ULONG32 ServiceIndex = 0;
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


		EThread = PsGetCurrentThread();
		PreviousMode = ChangePreviousMode(EThread);

		__try
		{
			if (NT_SUCCESS(__NtQueryObject((HANDLE)HandleValue, ObjectNameInfo, v5, 0x1000, &ReturnLength)))
			{
				POBJECT_NAME_INFORMATION v1 = (POBJECT_NAME_INFORMATION)v5;
				if (IsUnicodeStringValid(&v1->Name))
				{
					ULONG v7 = CmpAndGetStringLength(&v1->Name, MAX_PATH);
					wcsncpy(ObjectName, v1->Name.Buffer, v7);
				}
			}
		}
		__except (1)
		{
			KdPrint(("GetHandleObjectName catch __except\n"));
		}

		RecoverPreviousMode(EThread, PreviousMode);
		FreePoolWithTag(v5, 0);
	}
}

VOID ObGetTypeName(HANDLE HandleValue, ULONG_PTR ObjectValue, WCHAR* TypeName)
{
	PVOID v5 = NULL;
	PETHREAD EThread = NULL;
	CHAR PreviousMode = 0;
	v5 = AllocatePoolWithTag(PagedPool, 0x1000);
	if (v5)
	{
		ULONG ReturnLength = 0;
		
		memset(v5, 0, 0x1000);
		if (__NtQueryObject == NULL)
		{
			PSYSTEM_SERVICE_DESCRIPTOR_TABLE   SystemServiceDescriptorTable = NULL;
			ULONG32 ServiceIndex = 0;
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
		EThread = PsGetCurrentThread();
		PreviousMode = ChangePreviousMode(EThread);


		__try
		{
			if (NT_SUCCESS(__NtQueryObject((HANDLE)HandleValue, ObjectTypeInfo, v5, 0x1000, &ReturnLength)))
			{
				POBJECT_TYPE_INFORMATION v1 = (POBJECT_TYPE_INFORMATION)v5;
				if (IsUnicodeStringValid(&v1->TypeName))
				{
					ULONG v7 = CmpAndGetStringLength(&v1->TypeName, MAX_PATH);
					wcsncpy(TypeName, v1->TypeName.Buffer, v7);
				}
			}
		}
		__except (1)
		{
		
		}

		RecoverPreviousMode(EThread, PreviousMode);
		FreePoolWithTag(v5, 0);
	}
}
