#include "MemoryHelper.h"
#include "SystemHelper.h"


LPFN_NTUNMAPVIEWOFSECTION __NtUnmapViewOfSection = NULL;
LPFN_NTQUERYVIRTUALMEMORY __NtQueryVirtualMemory = NULL;
LPFN_NTPROTECTVIRTUALMEMORY  __NtProtectVirtualMemory = NULL;
void InitializeMemroySource()
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

	if (!GetNtXXXServcieIndex("NtQueryVirtualMemory", &ServiceIndex))
	{
		return;
	}
	if (!NT_SUCCESS(GetNtXXXServcieAddress(ServiceIndex, &__NtQueryVirtualMemory)))
	{
		return;
	}


	if (!GetNtXXXServcieIndex("NtProtectVirtualMemory", &ServiceIndex))
	{
		return;
	}
	if (!NT_SUCCESS(GetNtXXXServcieAddress(ServiceIndex, &__NtProtectVirtualMemory)))
	{
		return;
	}
}



BOOLEAN
MapFileInKernelSpace(WCHAR* FullPath,
	PVOID* VirtualAddress, PSIZE_T ViewSize)
{

	NTSTATUS          Status;
	UNICODE_STRING    v1;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK   IoStatusBlock;
	HANDLE   FileHandle = NULL;
	HANDLE   SectionHandle = NULL;

	if (!FullPath && MmIsAddressValid(FullPath))
	{
		return FALSE;
	}

	if (!VirtualAddress && MmIsAddressValid(VirtualAddress))
	{
		return FALSE;
	}


	//将文件路径转换成UNICODE_STRING存储
	RtlInitUnicodeString(&v1, FullPath);

	//根据UNICODE_STRING创建对象属性
	InitializeObjectAttributes(&ObjectAttributes,
		&v1,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);

	//获得文件句柄
	//zwcrete

	Status = IoCreateFile(&FileHandle,
		GENERIC_READ | SYNCHRONIZE,
		&ObjectAttributes,   //文件绝对路径
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_NO_PARAMETER_CHECKING
	);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	//根据文件句柄创建映射对象
	ObjectAttributes.ObjectName = NULL;

	//创建内存映射 
	Status = ZwCreateSection(&SectionHandle,
		SECTION_QUERY | SECTION_MAP_READ,
		&ObjectAttributes,
		NULL,
		PAGE_WRITECOPY,
		SEC_IMAGE, //内存对齐  0x1000
		FileHandle
	);
	ZwClose(FileHandle);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}
	Status = ZwMapViewOfSection(SectionHandle,
		NtCurrentProcess(),    //映射到当前进程的内存空间中
		VirtualAddress,
		0,
		0,
		0,
		ViewSize,
		ViewUnmap,
		0,
		PAGE_WRITECOPY
	);
	ZwClose(SectionHandle);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}
	return TRUE;
}






NTSTATUS VirtualProtect(PMDL* Mdl, PVOID VirtualAddress1, PSIZE_T ViewSize, PVOID* VirtualAddress2)
{

	*Mdl = MmCreateMdl(NULL, VirtualAddress1, ViewSize);

	if (!(*Mdl))
		return STATUS_UNSUCCESSFUL;

	MmBuildMdlForNonPagedPool(*Mdl);
	(*Mdl)->MdlFlags = (*Mdl)->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;

	*VirtualAddress2 = MmMapLockedPages(*Mdl, KernelMode);

	return STATUS_SUCCESS;
}

NTSTATUS UnvirtualProtect(PMDL Mdl, PVOID VirtualAddress2)
{
	if (Mdl)
	{
		MmUnmapLockedPages(VirtualAddress2, Mdl);
		IoFreeMdl(Mdl);
	}
}


NTSTATUS SafeCopyMemoryR32R0(ULONG_PTR Source, ULONG_PTR Destination, ULONG ViewSize)
{

	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	ULONG v1 = 0;
	ULONG v2 = PAGE_SIZE - (Source & 0xFFF);   //剩余部分


	if (KeGetCurrentIrql() <= APC_LEVEL &&
		Source <= _USER_ADDRESS_END_ &&
		Destination >= _SYSTEM_ADDRESS_START_ &&
		ViewSize > 0)
	{
		while (v1 < ViewSize)
		{
			PMDL Mdl = NULL;
			PVOID VirtualAddress = NULL;
			BOOLEAN IsOk = FALSE;

			if (ViewSize - v1 < v2)
			{
				v2 = ViewSize - v1;
			}
#ifdef _WIN64
			Mdl = IoAllocateMdl((PVOID)(Source & 0xFFFFFFFFFFFFF000), PAGE_SIZE, FALSE, FALSE, NULL);
#else

			Mdl = IoAllocateMdl((PVOID)(Source & 0xFFFFF000), PAGE_SIZE, FALSE, FALSE, NULL);
#endif // _WIN64


		
			if (Mdl)
			{
				__try
				{
					MmProbeAndLockPages(Mdl, UserMode, IoReadAccess);
					IsOk = TRUE;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					IsOk = FALSE;
				}

				if (IsOk)
				{
					VirtualAddress = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
					if (VirtualAddress)
					{
						RtlCopyMemory((PVOID)Destination, (PVOID)((ULONG_PTR)VirtualAddress + (Source & 0xFFF)), v2);
					}

					MmUnlockPages(Mdl);
				}

				IoFreeMdl(Mdl);
			}

			if (v1)
			{
				v2 = PAGE_SIZE;
			}

			v1 += v2;
			Source += v2;
			Destination += v2;
		}

		Status = STATUS_SUCCESS;
	}

	return Status;
}

NTSTATUS SafeCopyMemoryR02R3(PVOID Source, PVOID Destination, ULONG SizeOfImage)
{
	PMDL  Mdl1 = NULL, Mdl2 = NULL;
	PUCHAR VirtualAddress1 = NULL, VirtualAddress2 = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	Mdl1 = IoAllocateMdl(Source, SizeOfImage, FALSE, FALSE, NULL);
	if (!Mdl1)
	{
		return Status;
	}

	MmBuildMdlForNonPagedPool(Mdl1);

	VirtualAddress1 = MmGetSystemAddressForMdlSafe(Mdl1, NormalPagePriority);
	if (!VirtualAddress1)
	{
		IoFreeMdl(Mdl1);
		return Status;
	}

	Mdl2 = IoAllocateMdl(Destination, SizeOfImage, FALSE, FALSE, NULL);
	if (!Mdl2)
	{
		IoFreeMdl(Mdl1);
		return Status;
	}

	__try
	{
		MmProbeAndLockPages(Mdl2, UserMode, IoWriteAccess);
		VirtualAddress2 = MmGetSystemAddressForMdlSafe(Mdl2, NormalPagePriority);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	if (VirtualAddress2)
	{
		RtlCopyMemory(VirtualAddress2, VirtualAddress1, SizeOfImage);
		MmUnlockPages(Mdl2);
		Status = STATUS_SUCCESS;
	}

	IoFreeMdl(Mdl2);
	IoFreeMdl(Mdl1);

	return Status;
}