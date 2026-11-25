#include "ProcessMemory.h"
#include "ProcessHelper.h"
#include "SystemHelper.h"
#include "ObjectHelper.h"
#include "MemoryHelper.h"
#include "ProcessThread.h"
#include "MemoryHelper.h"

NTSTATUS PsEnumProcessMemorys(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{
	NTSTATUS Status1 = STATUS_UNSUCCESSFUL, Status2 = STATUS_UNSUCCESSFUL;
	PCOMMUNICATE_PROCESS_MEMORY v1 = (PCOMMUNICATE_PROCESS_MEMORY)InputBuffer;
	PEPROCESS EProcess = NULL;
	ULONG_PTR ProcessIdentity = 0;
	ULONG NumberOfMemory = (OutputBufferLength - sizeof(MEMORYS_INFORMATION)) / sizeof(MEMORY_INFORMATION);

	// 参数检测
	if (!InputBuffer ||
		InputBufferLength != sizeof(COMMUNICATE_PROCESS_MEMORY) ||
		!OutputBuffer ||
		OutputBufferLength < sizeof(MEMORYS_INFORMATION))
	{
		return STATUS_INVALID_PARAMETER;
	}

	ProcessIdentity = v1->u1.Query.ProcessIdentity;

	if (ProcessIdentity)
	{
		Status2 = PsLookupProcessByProcessId((HANDLE)ProcessIdentity, &EProcess);
	}
	if (PsIsRealProcess(EProcess))
	{
		
		Status1 = EnumProcessMemorys(EProcess, (PMEMORYS_INFORMATION)OutputBuffer, NumberOfMemory);
		if (NT_SUCCESS(Status1))
		{
			if (NumberOfMemory >= ((PMEMORYS_INFORMATION)OutputBuffer)->NumberOfMemory)
			{
				Status1 = STATUS_SUCCESS;
			}
			else
			{
				Status1 = STATUS_BUFFER_TOO_SMALL;
			}
		}
	}

	if (NT_SUCCESS(Status2))
	{
		ObfDereferenceObject(EProcess);
	}

	return Status1;
}

NTSTATUS EnumProcessMemorys(PEPROCESS EProcess, PMEMORYS_INFORMATION MemorysInfo, ULONG NumberOfMemory)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE ProcessHandle = NULL;
	PETHREAD EThread = NULL;
	CHAR PreviousMode = 0;
	Status = ObOpenObjectByPointer(EProcess,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		GENERIC_ALL,
		*PsProcessType,
		KernelMode,
		&ProcessHandle
	);

	if (NT_SUCCESS(Status))
	{
		PVOID VirtualAddress = 0;

		if (__NtQueryVirtualMemory == NULL)
		{
			PSYSTEM_SERVICE_DESCRIPTOR_TABLE   SystemServiceDescriptorTable = NULL;
			ULONG32 ServiceIndex = 0;
			SystemServiceDescriptorTable = GetKeServiceDescriptorTable();
			if (!GetNtXXXServcieIndex("NtQueryVirtualMemory", &ServiceIndex))
			{
				return;
			}
			if (!NT_SUCCESS(GetNtXXXServcieAddress(ServiceIndex, &__NtQueryVirtualMemory)))
			{
				return;
			}
		}



		EThread = PsGetCurrentThread();
		PreviousMode = ChangePreviousMode(EThread);
		ULONG_PTR v100 = MM_HIGHEST_USER_ADDRESS;
		while (VirtualAddress < MM_HIGHEST_USER_ADDRESS)
		{
			MEMORY_BASIC_INFORMATION MemoryBaseInfo;
			ULONG ReturnLength = 0;
			NTSTATUS Status2 = __NtQueryVirtualMemory(ProcessHandle,
				(PVOID)VirtualAddress,
				MemoryBasicInformation,
				&MemoryBaseInfo,
				sizeof(MEMORY_BASIC_INFORMATION),
				&ReturnLength);

			if (NT_SUCCESS(Status2))
			{
				ULONG v1 = MemorysInfo->NumberOfMemory;
				if (NumberOfMemory > v1)
				{
					MemorysInfo->MemoryInfo[v1].BaseAddress = VirtualAddress;
					MemorysInfo->MemoryInfo[v1].RegionSize = MemoryBaseInfo.RegionSize;
					MemorysInfo->MemoryInfo[v1].Protect = MemoryBaseInfo.Protect;
					MemorysInfo->MemoryInfo[v1].State = MemoryBaseInfo.State;
					MemorysInfo->MemoryInfo[v1].Type = MemoryBaseInfo.Type;
				}

				MemorysInfo->NumberOfMemory++;
				(PUINT8)VirtualAddress += MemoryBaseInfo.RegionSize;
			}
			else
			{
				(PUINT8)VirtualAddress += PAGE_SIZE;
			}
		}
		RecoverPreviousMode(EThread, PreviousMode);
		ZwClose(ProcessHandle);
		
	}

	return Status;
}
NTSTATUS PsReadProcessMemory(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{

	NTSTATUS  Status1 = STATUS_UNSUCCESSFUL;
	NTSTATUS  Status2 = STATUS_UNSUCCESSFUL;
	PEPROCESS EProcess;
	PVOID     BufferData = NULL;
	BOOLEAN   IsAttach = FALSE;
	KAPC_STATE ApcState;


	PCOMMUNICATE_PROCESS_MEMORY v1 = (PCOMMUNICATE_PROCESS_MEMORY)InputBuffer;
	if (!InputBuffer ||
		InputBufferLength != sizeof(COMMUNICATE_PROCESS_MEMORY) ||
		!OutputBuffer ||
		OutputBufferLength < MAX_LENGTH)
	{
		return STATUS_INVALID_PARAMETER;
	}
	if (v1->u1.Read.ProcessIdentity)
	{
		Status2 = PsLookupProcessByProcessId((HANDLE)v1->u1.Read.ProcessIdentity, &EProcess);

		if (NT_SUCCESS(Status2) && EProcess != NULL && PsIsRealProcess(EProcess))
		{
		
			BufferData = AllocatePoolWithTag(PagedPool, OutputBufferLength);
			if (BufferData == NULL)
			{
				return STATUS_UNSUCCESSFUL;
			}
			memset(BufferData, 0, OutputBufferLength);
			__try
			{

				ULONG_PTR ProcessIdentity = v1->u1.Read.ProcessIdentity;
				PVOID   BaseAddress = v1->u1.Read.BaseAddress;
				SIZE_T  RegionSize = v1->u1.Read.RegionSize;




				KeStackAttachProcess(EProcess, &ApcState);
				IsAttach = TRUE;

				ProbeForRead(BaseAddress, RegionSize, 1);
				memcpy(BufferData, (PVOID)BaseAddress, RegionSize);

				if (IsAttach)
				{
					KeUnstackDetachProcess(&ApcState);
					IsAttach = FALSE;
				}


				memcpy(OutputBuffer, BufferData, OutputBufferLength);

				if (BufferData != NULL)
				{
					FreePoolWithTag(BufferData);
				}

				Status1 = STATUS_SUCCESS;
			}

			__except (1)
			{
				if (IsAttach == TRUE)
				{
					KeUnstackDetachProcess(&ApcState);
				}

				if (BufferData != NULL)
				{
					FreePoolWithTag(BufferData);
				}

				Status1 = STATUS_UNSUCCESSFUL;
			}
		}
		if (NT_SUCCESS(Status2))
		{
			ObDereferenceObject(EProcess);
		}
		
	}

	return Status1;
}
NTSTATUS PsWriteProcessMemory(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{
	NTSTATUS  Status1 = STATUS_UNSUCCESSFUL;
	NTSTATUS  Status2 = STATUS_UNSUCCESSFUL;
	PEPROCESS EProcess = NULL;
	PVOID     BufferData = NULL;

	BOOLEAN   IsAttach = FALSE;
	KAPC_STATE ApcState;
	PETHREAD EThread;
	CHAR PreviousMode;
	HANDLE ProcessHandle = NULL;
	ULONG  OldProtect = 0;
	PCOMMUNICATE_PROCESS_MEMORY v1 = (PCOMMUNICATE_PROCESS_MEMORY)InputBuffer;
	if (!InputBuffer || InputBufferLength != sizeof(COMMUNICATE_PROCESS_MEMORY) + v1->u1.Write.RegionSize)
	{
		return STATUS_INVALID_PARAMETER;
	}
	if (v1->u1.Write.ProcessIdentity)
	{
		Status2 = PsLookupProcessByProcessId((HANDLE)v1->u1.Write.ProcessIdentity, &EProcess);

		if (NT_SUCCESS(Status2) && EProcess && PsIsRealProcess(EProcess))
		{
			BufferData = AllocatePoolWithTag(PagedPool, v1->u1.Write.RegionSize);
			if (BufferData == NULL)
			{
				return STATUS_UNSUCCESSFUL;
			}

			memcpy(BufferData, v1->u1.Write.BufferData, v1->u1.Write.RegionSize);
			__try
			{

				PVOID   BaseAddress = v1->u1.Write.BaseAddress;
				SIZE_T  RegionSize = v1->u1.Write.RegionSize;

				PVOID   v5 = BaseAddress;
				SIZE_T  v7 = RegionSize;

				KeStackAttachProcess(EProcess, &ApcState);
				IsAttach = TRUE;

				__try
				{
					memcpy((PVOID)BaseAddress, (PVOID)BufferData, RegionSize);    //修改目标进程数据   ReadOnly

					if (IsAttach)
					{
						KeUnstackDetachProcess(&ApcState);
						IsAttach = FALSE;
					}

					if (BufferData != NULL)
					{
						FreePoolWithTag(BufferData);
					}

					Status1 = STATUS_SUCCESS;

				}
				__except (1)
				{
					if (IsAttach)
					{
						KeUnstackDetachProcess(&ApcState);
						IsAttach = FALSE;
					}
					EThread = PsGetCurrentThread();
					PreviousMode = ChangePreviousMode(EThread);


					Status1 = ObOpenObjectByPointer(EProcess,
						OBJ_KERNEL_HANDLE, NULL, GENERIC_ALL, *PsProcessType, KernelMode, &ProcessHandle);

					if (!NT_SUCCESS(Status1))
					{
						RecoverPreviousMode(EThread, PreviousMode);
						if (BufferData != NULL)
						{
							FreePoolWithTag(BufferData);
						}

						Status1 = STATUS_UNSUCCESSFUL;
					}
					else
					{


						if (__NtProtectVirtualMemory == NULL)
						{
							PSYSTEM_SERVICE_DESCRIPTOR_TABLE   SystemServiceDescriptorTable = NULL;
							ULONG32 ServiceIndex = 0;
							SystemServiceDescriptorTable = GetKeServiceDescriptorTable();
							if (!GetNtXXXServcieIndex("NtProtectVirtualMemory", &ServiceIndex))
							{
								Status1 = STATUS_UNSUCCESSFUL;
							}
							if (!NT_SUCCESS(GetNtXXXServcieAddress(ServiceIndex, &__NtProtectVirtualMemory)))
							{
								Status1 = STATUS_UNSUCCESSFUL;
							}
						}

						if (__NtProtectVirtualMemory != NULL)
						{
							Status1 = __NtProtectVirtualMemory(ProcessHandle,
								&v5, &v7, PAGE_READWRITE, &OldProtect);

							if (!NT_SUCCESS(Status1))
							{
								RecoverPreviousMode(EThread, PreviousMode);
								ZwClose(ProcessHandle);

								if (BufferData != NULL)
								{
									FreePoolWithTag(BufferData);
								}

								Status1 = STATUS_UNSUCCESSFUL;
							}
							else
							{
								__try
								{
									KeStackAttachProcess(EProcess, &ApcState);
									IsAttach = TRUE;
									memcpy((PVOID)BaseAddress, (PVOID)BufferData, RegionSize);    //修改目标进程数据   ReadOnly

									if (IsAttach)
									{
										KeUnstackDetachProcess(&ApcState);
										IsAttach = FALSE;
									}


									EThread = PsGetCurrentThread();
									PreviousMode = ChangePreviousMode(EThread);

									Status1 = __NtProtectVirtualMemory(ProcessHandle,
										&v5, &v7, OldProtect, NULL);

									RecoverPreviousMode(EThread, PreviousMode);

									ZwClose(ProcessHandle);

									if (BufferData != NULL)
									{
										ExFreePool(BufferData);
									}

								}
								__except (1)
								{
									if (IsAttach)
									{
										KeUnstackDetachProcess(&ApcState);
										IsAttach = FALSE;
									}
									if (BufferData != NULL)
									{
										FreePoolWithTag(BufferData);
									}

									Status1 = STATUS_UNSUCCESSFUL;
								}
							}
							RecoverPreviousMode(EThread, PreviousMode);
						}
					}
				}
			}
			__except (1)
			{
				if (IsAttach)
				{
					KeUnstackDetachProcess(&ApcState);
					IsAttach = FALSE;
				}

				if (BufferData != NULL)
				{
					FreePoolWithTag(BufferData);
				}
				Status1 = STATUS_UNSUCCESSFUL;
			}
		}
	}

	if (NT_SUCCESS(Status2))
	{
		ObDereferenceObject(EProcess);
	}
	return Status1;
}

NTSTATUS PsModifyProcessMemory(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{
	NTSTATUS Status1 = STATUS_UNSUCCESSFUL, Status2 = STATUS_UNSUCCESSFUL;
	PCOMMUNICATE_PROCESS_MEMORY v1 = (PCOMMUNICATE_PROCESS_MEMORY)InputBuffer;
	PEPROCESS EProcess = NULL;
	ULONG_PTR ProcessIdentity = 0;
	HANDLE ProcessHandle;
	ULONG NewProtect = 0;
	PVOID BaseAddress = NULL;
	SIZE_T RegionSize = 0;
	// 参数检查
	if (!InputBuffer || InputBufferLength != sizeof(COMMUNICATE_PROCESS_MEMORY))
	{
		return STATUS_INVALID_PARAMETER;
	}

	BaseAddress = v1->u1.Modify.BaseAddress;
	RegionSize = v1->u1.Modify.RegionSize;
	NewProtect = v1->u1.Modify.NewProtect;;
	ProcessIdentity = v1->u1.Modify.ProcessIdentity;


	if (BaseAddress > _USER_ADDRESS_END_ ||
		RegionSize >= _SYSTEM_ADDRESS_START_ ||
		(ULONG_PTR)BaseAddress + RegionSize >= _SYSTEM_ADDRESS_START_
		)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (ProcessIdentity)
	{
		Status2 = PsLookupProcessByProcessId((HANDLE)ProcessIdentity, &EProcess);
	}

	if (PsIsRealProcess(EProcess))
	{

		Status1 = ObOpenObjectByPointer(EProcess,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			GENERIC_ALL,
			*PsProcessType,
			KernelMode,
			&ProcessHandle);

		if (NT_SUCCESS(Status1))
		{
		
			ULONG ulOldProtect = 0;

			if (__NtProtectVirtualMemory == NULL)
			{
				PSYSTEM_SERVICE_DESCRIPTOR_TABLE   SystemServiceDescriptorTable = NULL;
				ULONG32 ServiceIndex = 0;
				SystemServiceDescriptorTable = GetKeServiceDescriptorTable();
				if (!GetNtXXXServcieIndex("NtProtectVirtualMemory", &ServiceIndex))
				{
					Status1 = STATUS_UNSUCCESSFUL;
				}
				if (!NT_SUCCESS(GetNtXXXServcieAddress(ServiceIndex, &__NtProtectVirtualMemory)))
				{
					Status1 = STATUS_UNSUCCESSFUL;
				}
			}
			if (__NtProtectVirtualMemory != NULL)
			{
				PETHREAD EThread = PsGetCurrentThread();
				CHAR PreviousMode = ChangePreviousMode(EThread);
				Status1 = __NtProtectVirtualMemory(ProcessHandle,
					&((PVOID)BaseAddress), &RegionSize, NewProtect, (PULONG)OutputBuffer);

				RecoverPreviousMode(EThread, PreviousMode);
			}
	
			ZwClose(ProcessHandle);		
		}
		
	}
	if (NT_SUCCESS(Status2))
	{
		ObfDereferenceObject(EProcess);
	}

	return Status1;
}