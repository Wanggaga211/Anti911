#include "ProcessModule.h"
#include "ProcessHelper.h"
#include "SystemHelper.h"
#include "MemoryHelper.h"
#include "StringHelper.h"
#include "ProcessThread.h"
#include "ObjectHelper.h"

NTSTATUS PsEnumProcessModules(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{
	NTSTATUS Status1 = STATUS_UNSUCCESSFUL, Status2 = STATUS_UNSUCCESSFUL;
	PCOMMUNICATE_PROCESS_MODULE v1 = (PCOMMUNICATE_PROCESS_MODULE)InputBuffer;
	ULONG_PTR ProcessIdentity = v1->ProcessIdentity;
	PEPROCESS EProcess = NULL;
	ULONG NumberOfModule = (OutputBufferLength - sizeof(MODULES_INFORMATION)) / sizeof(MODULE_INFORMATION);

	// 参数检查
	if (!InputBuffer ||
		InputBufferLength != sizeof(COMMUNICATE_PROCESS_MODULE) ||
		!OutputBuffer ||
		OutputBufferLength < sizeof(MODULES_INFORMATION))
	{
		return STATUS_INVALID_PARAMETER;
	}

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
		PMODULES_INFORMATION v5 = (PMODULES_INFORMATION)AllocatePoolWithTag(PagedPool, OutputBufferLength);
		if (v5)
		{
			memset(v5, 0, OutputBufferLength);

			//进程Peb
			Status1 = EnumProcessModulesByPeb(EProcess, v5, NumberOfModule);




			if (NumberOfModule >= v5->NumberOfModule)
			{
				RtlCopyMemory(OutputBuffer, v5, OutputBufferLength);
				Status1 = STATUS_SUCCESS;
			}
			else
			{
				Status1 = STATUS_BUFFER_TOO_SMALL;
			}

			FreePoolWithTag(v5, 0);
			v5 = NULL;
		}
	}

	if (NT_SUCCESS(Status2))
	{
		ObfDereferenceObject(EProcess);
	}

	return Status1;
}
NTSTATUS PsDumpProcessModule(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{
	NTSTATUS Status1 = STATUS_UNSUCCESSFUL, Status2 = STATUS_UNSUCCESSFUL;
	PCOMMUNICATE_PROCESS_MODULE v1 = (PCOMMUNICATE_PROCESS_MODULE)InputBuffer;
	PEPROCESS EProcess = NULL, EProcessTemp = NULL;
	ULONG_PTR ModuleBase = 0;
	ULONG SizeOfImage = 0;
	ULONG_PTR ProcessIdentity = 0;
	
	// 参数检查
	if (!InputBuffer ||
		InputBufferLength != sizeof(COMMUNICATE_PROCESS_MODULE) ||
		!OutputBuffer ||
		!OutputBufferLength)
	{
		return STATUS_INVALID_PARAMETER;
	}

	
	ModuleBase = v1->u1.Dump.ModuleBase;
	SizeOfImage = v1->u1.Dump.SizeOfImage;
	ProcessIdentity = v1->ProcessIdentity;

	if (SizeOfImage == 0 ||
		ModuleBase > _USER_ADDRESS_END_ ||
		SizeOfImage > _USER_ADDRESS_END_ ||
		ModuleBase + SizeOfImage > _USER_ADDRESS_END_)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (ProcessIdentity)
	{
		Status2 = PsLookupProcessByProcessId((HANDLE)ProcessIdentity, &EProcess);
	}

	if (!EProcess)
	{
		return Status1;
	}


	if (PsIsRealProcess(EProcess))
	{
		Status1 = SafeCopyProcessModule(EProcess, ModuleBase, SizeOfImage, OutputBuffer);
	}

	if (NT_SUCCESS(Status2))
	{
		ObfDereferenceObject(EProcess);
	}

	return Status1;
}
NTSTATUS PsUnloadProcessModule(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{
	NTSTATUS Status1 = STATUS_UNSUCCESSFUL, Status2 = STATUS_UNSUCCESSFUL;
	PCOMMUNICATE_PROCESS_MODULE v1 = (PCOMMUNICATE_PROCESS_MODULE)InputBuffer;
	PEPROCESS EProcess = NULL;
	ULONG_PTR ProcessIdentity = 0, ModuleBase = 0;
	
	// 检查参数
	if (!InputBuffer || InputBufferLength != sizeof(COMMUNICATE_PROCESS_MODULE))
	{
		return STATUS_INVALID_PARAMETER;
	}

	ProcessIdentity = v1->ProcessIdentity;
	ModuleBase = v1->u1.Unload.ModuleBase;
	if (ProcessIdentity)
	{
		Status2 = PsLookupProcessByProcessId((HANDLE)ProcessIdentity, &EProcess);
	}

	if (!EProcess)
	{
		return Status1;
	}

	if (PsIsRealProcess(EProcess))
	{
		HANDLE ProcessHandle = NULL;

		Status1 = ObOpenObjectByPointer(EProcess,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			GENERIC_ALL,
			*PsProcessType,
			KernelMode,
			&ProcessHandle
		);

		if (NT_SUCCESS(Status1))
		{


			if (__NtUnmapViewOfSection == NULL || __NtClose == NULL)
			{
				PSYSTEM_SERVICE_DESCRIPTOR_TABLE   SystemServiceDescriptorTable = NULL;
				ULONG32 ServiceIndex = 0;
				SystemServiceDescriptorTable = GetKeServiceDescriptorTable();


				if (!GetNtXXXServcieIndex("NtUnmapViewOfSection", &ServiceIndex))
				{
					return;
				}
				if (!NT_SUCCESS(GetNtXXXServcieAddress(ServiceIndex, &__NtUnmapViewOfSection)))
				{
					return;
				}
				if (!GetNtXXXServcieIndex("NtClose", &ServiceIndex))
				{
					return;
				}
				if (!NT_SUCCESS(GetNtXXXServcieAddress(ServiceIndex, &__NtClose)))
				{
					return;
				}
			}
			PETHREAD EThread = PsGetCurrentThread();
			CHAR PreviousMode = ChangePreviousMode(EThread);

			Status1 = __NtUnmapViewOfSection(ProcessHandle, (PVOID)ModuleBase);
			if (NT_SUCCESS(Status1))
			{
				RemoveProcessModuleInPeb(EProcess, ModuleBase);
			
			}

			__NtClose(ProcessHandle);
			RecoverPreviousMode(EThread, PreviousMode);
		}
	}

	if (NT_SUCCESS(Status2))
	{
		ObfDereferenceObject(EProcess);
	}

	return Status1;
}
NTSTATUS EnumProcessModulesByPeb(PEPROCESS EProcess, PMODULES_INFORMATION ModulesInfo, ULONG NumberOfModule)
{
	BOOLEAN IsAttach = FALSE;
	KAPC_STATE ApcState;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	if (
		!EProcess || !ModulesInfo ||
		!NumberOfModule ||
		KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return Status;
	}
#ifdef _WIN64
	ULONG_PTR Offset = 0x338;
#else
	ULONG_PTR Offset = 0x1a8;
#endif 
	if (!MmIsAddressValid((PVOID)((ULONG_PTR)EProcess + Offset)))
	{
		return Status;
	}

	if (IoGetCurrentProcess() != EProcess)
	{
		KeStackAttachProcess(EProcess, &ApcState);
		IsAttach = TRUE;
	}

	__try
	{
		PPEB Peb = *((PPEB*)((ULONG_PTR)EProcess + Offset));

		if ((ULONG_PTR)Peb > 0 && (ULONG_PTR)Peb <= _USER_ADDRESS_END_)
		{
			PPEB_LDR_DATA PebLdrData = NULL;

			ProbeForRead(Peb, sizeof(PEB), 1);
			ProbeForRead(Peb->Ldr, sizeof(PEB_LDR_DATA), 1);

			PebLdrData = (PPEB_LDR_DATA)(Peb->Ldr);

			if ((ULONG_PTR)PebLdrData > 0 && (ULONG_PTR)PebLdrData <= _USER_ADDRESS_END_)
			{
				WalkerModuleList1(&PebLdrData->InLoadOrderModuleList, 1, ModulesInfo, NumberOfModule);
				WalkerModuleList1(&PebLdrData->InMemoryOrderModuleList, 2, ModulesInfo, NumberOfModule);
				WalkerModuleList1(&PebLdrData->InInitializationOrderModuleList, 3, ModulesInfo, NumberOfModule);

				Status = STATUS_SUCCESS;
			}
		}
	}
	__except (1)
	{
		
		Status = STATUS_UNSUCCESSFUL;
	}

	if (IsAttach)
	{
		KeUnstackDetachProcess(&ApcState);
		IsAttach = FALSE;
	}

	return Status;
}
NTSTATUS RemoveProcessModuleInPeb(PEPROCESS EProcess, ULONG_PTR ModuleBase)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	if (EProcess && KeGetCurrentIrql() < DISPATCH_LEVEL)
	{

#ifdef _WIN64
		ULONG_PTR Offset = 0x338;
#else
		ULONG_PTR Offset = 0x1a8;
#endif 
		BOOLEAN IsAttach = FALSE;
		KAPC_STATE ApcState;

		if (!MmIsAddressValid((PVOID)((ULONG_PTR)EProcess + Offset)))
		{
			return Status;
		}

		if (IoGetCurrentProcess() != EProcess)
		{
			KeStackAttachProcess(EProcess, &ApcState);
			IsAttach = TRUE;
		}

		__try
		{
			PPEB Peb = *(PPEB*)((ULONG_PTR)EProcess + Offset);
			if ((ULONG_PTR)Peb > 0 && (ULONG_PTR)Peb <= _USER_ADDRESS_END_)
			{
				PPEB_LDR_DATA PebLdrData = NULL;

				ProbeForRead(Peb, sizeof(PEB), 1);
				ProbeForRead(Peb->Ldr, sizeof(PEB_LDR_DATA), 1);

				PebLdrData = (PPEB_LDR_DATA)(Peb->Ldr);
				if ((ULONG_PTR)PebLdrData > 0 && (ULONG_PTR)PebLdrData < _SYSTEM_ADDRESS_START_)
				{
					WalkerModuleList2(&PebLdrData->InLoadOrderModuleList, 1, ModuleBase);
					WalkerModuleList2(&PebLdrData->InMemoryOrderModuleList, 2, ModuleBase);
					WalkerModuleList2(&PebLdrData->InInitializationOrderModuleList, 3, ModuleBase);

					Status = STATUS_SUCCESS;
				}
			}
		}
		__except (1)
		{
			
		}

		if (IsAttach)
		{
			KeUnstackDetachProcess(&ApcState);
			IsAttach = FALSE;
		}
	}

	return Status;
}

NTSTATUS SafeCopyProcessModule(PEPROCESS EProcess, ULONG_PTR ModuleBase, ULONG SizeOfImage, PVOID OutputBuffer)
{
	BOOLEAN IsAttach = FALSE;
	KAPC_STATE ApcState;
	PVOID v5 = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (SizeOfImage == 0 || OutputBuffer == NULL || EProcess == NULL)
	{
		return Status;
	}



	v5 = AllocatePoolWithTag(NonPagedPool, SizeOfImage);
	if (!v5)
	{
		return Status;
	}

	memset(v5, 0, SizeOfImage);

	if (EProcess != IoGetCurrentProcess())
	{
		KeStackAttachProcess(EProcess, &ApcState);
		IsAttach = TRUE;
	}

	Status = SafeCopyMemoryR32R0(ModuleBase, (ULONG_PTR)v5, SizeOfImage);

	if (IsAttach)
	{
		KeUnstackDetachProcess(&ApcState);
		IsAttach = FALSE;
	}

	if (NT_SUCCESS(Status))
	{
		Status = SafeCopyMemoryR02R3(v5, OutputBuffer, SizeOfImage);
	}

	if (v5)
	{
		FreePoolWithTag(v5, 0);
		v5 = NULL;
	}

	return Status;
}

void WalkerModuleList1(PLIST_ENTRY ListEntry, ULONG EnumType, PMODULES_INFORMATION ModulesInfo, ULONG NumberOfModule)
{
	PLIST_ENTRY v1 = NULL;

	v1 = ListEntry->Flink;

	while ((ULONG_PTR)v1 > 0 && (ULONG_PTR)v1 <= _USER_ADDRESS_END_ && v1 != ListEntry)
	{
		PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = NULL;

		switch (EnumType)
		{
		case 1:
			LdrDataTableEntry = CONTAINING_RECORD(v1, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			break;

		case 2:
			LdrDataTableEntry = CONTAINING_RECORD(v1, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			break;

		case 3:
			LdrDataTableEntry = CONTAINING_RECORD(v1, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
			break;
		}

		if ((ULONG_PTR)LdrDataTableEntry > 0 && (ULONG_PTR)LdrDataTableEntry <= _USER_ADDRESS_END_)
		{
			__try
			{
				ProbeForRead(LdrDataTableEntry, sizeof(LDR_DATA_TABLE_ENTRY), 1);

				if (!IsModuleInList((ULONG_PTR)LdrDataTableEntry->DllBase, LdrDataTableEntry->SizeOfImage, ModulesInfo, NumberOfModule))
				{
					if (NumberOfModule > ModulesInfo->NumberOfModule)
					{
						ULONG Length = CmpAndGetStringLength(&LdrDataTableEntry->FullDllName, MAX_PATH);

						ModulesInfo->ModuleInfo[ModulesInfo->NumberOfModule].ModuleBase = (ULONG_PTR)LdrDataTableEntry->DllBase;
						ModulesInfo->ModuleInfo[ModulesInfo->NumberOfModule].SizeOfImage = LdrDataTableEntry->SizeOfImage;

						ProbeForRead(LdrDataTableEntry->FullDllName.Buffer, Length * sizeof(WCHAR), sizeof(WCHAR));

						wcsncpy(ModulesInfo->ModuleInfo[ModulesInfo->NumberOfModule].ModulePath, LdrDataTableEntry->FullDllName.Buffer, Length);
					}

					ModulesInfo->NumberOfModule++;
				}
			}
			__except (1)
			{
				
			}
		}

		v1 = v1->Flink;
	}
}
VOID WalkerModuleList2(PLIST_ENTRY ListEntry, ULONG EnumType, ULONG_PTR ModuleBase)
{
	PLIST_ENTRY v1 = NULL;

	v1 = ListEntry->Flink;

	while ((ULONG_PTR)v1 > 0 && (ULONG_PTR)v1 <= _USER_ADDRESS_END_ && v1 != ListEntry)
	{
		PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = NULL;

		switch (EnumType)
		{
		case 1:
			LdrDataTableEntry = CONTAINING_RECORD(v1, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			break;

		case 2:
			LdrDataTableEntry = CONTAINING_RECORD(v1, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			break;

		case 3:
			LdrDataTableEntry = CONTAINING_RECORD(v1, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
			break;
		}

		if ((ULONG_PTR)LdrDataTableEntry > 0 && (ULONG_PTR)LdrDataTableEntry <= _USER_ADDRESS_END_)
		{
			__try
			{
				ProbeForRead(LdrDataTableEntry, sizeof(LDR_DATA_TABLE_ENTRY), 1);

				if ((ULONG_PTR)LdrDataTableEntry->DllBase == ModuleBase &&
					(ULONG_PTR)v1->Blink <= _USER_ADDRESS_END_ &&
					(ULONG_PTR)v1->Flink <= _USER_ADDRESS_END_)
				{
					RemoveEntryList(v1);
					break;
				}
			}
			__except (1)
			{
				
			}
		}

		v1 = v1->Flink;
	}
}
BOOLEAN IsModuleInList(ULONG_PTR ModuleBase, ULONG SizeOfImage, PMODULES_INFORMATION ModulesInfo, ULONG NumberOfModule)
{
	BOOLEAN IsOk = FALSE;
	ULONG i = 0;
	ULONG v1 = ModulesInfo->NumberOfModule > NumberOfModule ? NumberOfModule : ModulesInfo->NumberOfModule;

	for (i = 0; i < v1; i++)
	{
		if (ModuleBase == ModulesInfo->ModuleInfo[i].ModuleBase && SizeOfImage == ModulesInfo->ModuleInfo[i].SizeOfImage)
		{
			IsOk = TRUE;
			break;
		}
	}

	return IsOk;
}