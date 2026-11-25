#include "SystemHelper.h"
#include "ProcessHelper.h"
#include "PeHelper.h"
#include "MemoryHelper.h"
#include "StringHelper.h"
#include "StackBackTrace.h"

PEPROCESS __System = NULL;
PVOID __Ntoskrnl = NULL;
ULONG  __ImageSize = 0;
UNICODE_STRING __NtoskrnlPath = { 0 };
PSYSTEM_SERVICE_DESCRIPTOR_TABLE __SystemServiceDescriptorTable = NULL;
LPFN_NTQUERYSYSTEMINFORMATION   __NtQuerySystemInformation = NULL;
VOID InitializeSystemSource()
{
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE   SystemServiceDescriptorTable = NULL;
	ULONG32 ServiceIndex = 0;

	__System = PsGetCurrentProcess();
	SystemServiceDescriptorTable = GetKeServiceDescriptorTable();
	if (__NtQuerySystemInformation == NULL)
	{
		if (!GetNtXXXServcieIndex("NtQuerySystemInformation", &ServiceIndex))
		{
			return;
		}
		if (!NT_SUCCESS(GetNtXXXServcieAddress(ServiceIndex,&__NtQuerySystemInformation)))
		{
			return;
		}
	}

	
	
}
PVOID GetNtoskrnlInfo(OUT PUNICODE_STRING NtoskrnlPath, OUT PULONG ImageSize)
{

	NTSTATUS Status = STATUS_SUCCESS;
	ULONG ReturnLength = 0;
	PRTL_PROCESS_MODULES RtlProcessModules = NULL;
	PVOID v1 = NULL;
	UNICODE_STRING ServiceName;
	ANSI_STRING v2;

	if (__Ntoskrnl != NULL)
	{
		if (ImageSize)
			*ImageSize = __ImageSize;

		if (NtoskrnlPath)
		{
			UnicodeStringCopy2UnicodeString(NtoskrnlPath, &__NtoskrnlPath);
		}

		return __Ntoskrnl;
	}

	//从系统第1个模块中的导出表中获取ZwOpenProcess
	RtlInitUnicodeString(&ServiceName, L"ZwOpenProcess");

	//从模块导出表中获得地址
	v1 = MmGetSystemRoutineAddress(&ServiceName);
	if (v1 == NULL)
	{
		return NULL;
	}

	//预查系统信息
	Status = ZwQuerySystemInformation(SystemModuleInformation, 0, ReturnLength, &ReturnLength);
	if (ReturnLength == 0)
	{

		return NULL;
	}
	//动态申请内存  
	RtlProcessModules = (PRTL_PROCESS_MODULES)AllocatePoolWithTag(PagedPool, ReturnLength);
	RtlZeroMemory(RtlProcessModules, ReturnLength);

	Status = ZwQuerySystemInformation(SystemModuleInformation, RtlProcessModules, ReturnLength, &ReturnLength);
	if (NT_SUCCESS(Status))
	{
		//
		PRTL_PROCESS_MODULE_INFORMATION RtlProcessModuleInfo = RtlProcessModules->Modules;

		for (ULONG i = 0; i < RtlProcessModules->NumberOfModules; i++)
		{

			if (v1 >= RtlProcessModuleInfo[i].ImageBase &&
				v1 < (PVOID)((PUCHAR)RtlProcessModuleInfo[i].ImageBase + RtlProcessModuleInfo[i].ImageViewSize))
			{
				//获取到了系统第1模块信息
				__Ntoskrnl = RtlProcessModuleInfo[i].ImageBase;
				__ImageSize = RtlProcessModuleInfo[i].ImageViewSize;


				RtlInitAnsiString(&v2, RtlProcessModuleInfo[i].FullPathName);

				//单字转换为UnicodeString
				RtlAnsiStringToUnicodeString(&__NtoskrnlPath, &v2, TRUE);

				if (ImageSize)
				{
					*ImageSize = __ImageSize;
				}


				if (NtoskrnlPath)
				{
					UnicodeStringCopy2UnicodeString(NtoskrnlPath, &__NtoskrnlPath);
				}
				break;
			}
		}
	}
	if (RtlProcessModules)
	{
		FreePoolWithTag(RtlProcessModules);
	}
	return __Ntoskrnl;
}
PVOID GetModuleHandle(PCHAR ModuleName)
{
	PVOID VirtualAddress = NULL;
	ULONG ViewSize = 0;
	PSYSTEM_MODULE_INFORMATION SystemModuleInfo;
	ULONG i;

	if (STATUS_INFO_LENGTH_MISMATCH == ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &ViewSize))
	{
		VirtualAddress = AllocatePoolWithTag(NonPagedPool, ViewSize);
		if (VirtualAddress)
		{
			ZwQuerySystemInformation(SystemModuleInformation, VirtualAddress, ViewSize, 0);
		}
		else
		{
			return NULL;
		}
	}
	else
	{
		return NULL;
	}

	SystemModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAddress;
	for (i = 0; i < SystemModuleInfo->NumberOfModule; i++)
	{
		_strlwr(ModuleName);
		_strlwr(SystemModuleInfo->Module[i].ModuleName);
	
		if (strstr(SystemModuleInfo->Module[i].ModuleName, ModuleName))
		{
			PVOID v5;
			v5 = SystemModuleInfo->Module[i].ModuleBaseAddress;
			FreePoolWithTag(VirtualAddress);
			return v5;
		}
	}
	FreePoolWithTag(VirtualAddress);
	return NULL;
}




PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetKeServiceDescriptorTable()
{

#ifdef  _WIN64
	ULONG ImageSize = 0;
	PUCHAR Ntoskrnl = NULL;
	if (!__Ntoskrnl)
	{

		Ntoskrnl = GetNtoskrnlInfo(NULL, &ImageSize);  //系统的内核第一模块
	}
	else
	{
		Ntoskrnl = __Ntoskrnl;
	}
	PIMAGE_NT_HEADERS64   ImageNtHeaders = RtlImageNtHeader(Ntoskrnl);
	PIMAGE_SECTION_HEADER ImageSectionHeader = (PIMAGE_SECTION_HEADER)(ImageNtHeaders + 1);


	for (PIMAGE_SECTION_HEADER v1 = ImageSectionHeader;
		v1 < ImageSectionHeader + ImageNtHeaders->FileHeader.NumberOfSections;
		v1++)
	{
		//未分页 未丢弃 可读节
		if (v1->Characteristics & IMAGE_SCN_MEM_NOT_PAGED &&
			v1->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
			!(v1->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
			(*(PULONG)v1->Name != 'TINI') &&
			(*(PULONG)v1->Name != 'EGAP'))
		{
			PVOID ReturnAddress = NULL;


			UCHAR PatternValue[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";
			NTSTATUS Status = SearchPattern2(
				PatternValue,
				0xCC,
				sizeof(PatternValue) - 1,
				Ntoskrnl + ImageSectionHeader->VirtualAddress,    //From
				ImageSectionHeader->Misc.VirtualSize,               //To
				&ReturnAddress);
			/*
//IDA PCHunter 模块 Sequence Of Bytes
text:0000000140074CF2 4C 8D 15 47 8C 23 00          lea     r10, KeServiceDescriptorTable
.text:0000000140074CF9 4C 8D 1D 80 8C 23 00          lea     r11, KeServiceDescriptorTableShadow
.text:0000000140074D00 F7 83 00 01 00 00 80 00 00 00 test    dword ptr [rbx+100h], 80h

			*/

			if (NT_SUCCESS(Status))
			{
				__SystemServiceDescriptorTable = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)ReturnAddress + *(PULONG)((PUCHAR)ReturnAddress + 3) + 7);

				return __SystemServiceDescriptorTable;
			}
		}
	}

#else

	extern PSYSTEM_SERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;   //是一个全局导出的变量

	__SystemServiceDescriptorTable = KeServiceDescriptorTable;

	/*
	3: kd > dd KeServiceDescriptorTable
	849a5b00  848ba43c 00000000 00000191 848baa84

	*/

	return __SystemServiceDescriptorTable;

#endif //  _WIN64



	return NULL;
}
BOOLEAN GetNtXXXServcieIndex(CHAR* FunctionName,
	ULONG32* ServiceIndex)
{
	/*
	0:007> u ZwTerminateProcess
ntdll!NtTerminateProcess:
00000000`77621570 4c8bd1          mov     r10,rcx
00000000`77621573 b829000000      mov     eax,29h
00000000`77621578 0f05            syscall
00000000`7762157a c3              ret
	*/

	ULONG    i;
	BOOLEAN  IsOk = FALSE;
	WCHAR	 FullPath[] = L"\\SystemRoot\\System32\\ntdll.dll";     //C:\Windows\  
	PVOID    VirtualAddress = NULL;
	SIZE_T   ViewSize = 0;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = NULL;
	PIMAGE_NT_HEADERS  ImageNtHeaders = NULL;
	UINT32* AddressOfFunctions = NULL;
	UINT32* AddressOfNames = NULL;
	UINT16* AddressOfNameOrdinals = NULL;
	CHAR* v1 = NULL;
	ULONG32  Ordinals = 0;
	PVOID    FunctionAddress = 0;


#ifdef _WIN64
	ULONG32  Offset = 4;
#else 
	ULONG32  Offset = 1;
#endif // 

	* ServiceIndex = -1;
	IsOk = MapFileInKernelSpace(FullPath,
		&VirtualAddress, &ViewSize);
	if (IsOk == FALSE)
	{
		return FALSE;
	}
	else
	{
		__try {
			ImageNtHeaders = RtlImageNtHeader(VirtualAddress);
			if (ImageNtHeaders && ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			{
				ImageExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((UINT8*)VirtualAddress +
					ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

				AddressOfFunctions = (UINT32*)((UINT8*)VirtualAddress + ImageExportDirectory->AddressOfFunctions);
				AddressOfNames = (UINT32*)((UINT8*)VirtualAddress + ImageExportDirectory->AddressOfNames);
				AddressOfNameOrdinals = (UINT16*)((UINT8*)VirtualAddress + ImageExportDirectory->AddressOfNameOrdinals);
				for (i = 0; i < ImageExportDirectory->NumberOfNames; i++)
				{
					v1 = (char*)((ULONG_PTR)VirtualAddress + AddressOfNames[i]);   //获得函数名称
					if (_stricmp(FunctionName, v1) == 0)
					{
						Ordinals = AddressOfNameOrdinals[i];
						FunctionAddress = (PVOID)((UINT8*)VirtualAddress + AddressOfFunctions[Ordinals]);


						*ServiceIndex = *(ULONG32*)((UINT8*)FunctionAddress + Offset);
						break;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			;
		}
	}
	ZwUnmapViewOfSection(NtCurrentProcess(), VirtualAddress);  //解除映射
	if (*ServiceIndex == -1)
	{
		return FALSE;
	}

	return TRUE;
}

NTSTATUS GetNtXXXServcieAddress(ULONG_PTR ServiceIndex, PVOID* ServiceAddress)
{
	PVOID v2 = NULL;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE SystemServiceDescriptorTable = NULL;
	PVOID* ServiceTableBase = NULL;


	if (__SystemServiceDescriptorTable == NULL)
	{
		SystemServiceDescriptorTable = GetKeServiceDescriptorTable();
	}
	else
	{
		SystemServiceDescriptorTable = __SystemServiceDescriptorTable;
	}

	ServiceTableBase = (PVOID*)(SystemServiceDescriptorTable->ServiceTableBase);

	if (ServiceTableBase != NULL)
	{
#ifdef  _WIN64


		if (ServiceIndex <= SystemServiceDescriptorTable->NumberOfServices)
		{
			LONG v1 = ((PULONG)ServiceTableBase)[ServiceIndex];
			v1 = v1 >> 4;
			v2 = (ULONGLONG)ServiceTableBase + (LONGLONG)v1;
		}
#else
		if (ServiceIndex <= SystemServiceDescriptorTable->NumberOfServices)
		{
			v2 = (SystemServiceDescriptorTable->ServiceTableBase)[ServiceIndex];

		}

#endif //  _WIN64

		//对该函数地址进行校验
		if (MmIsAddressValid(v2))
		{
			if (ServiceAddress != NULL)
			{
				*ServiceAddress = v2;
				return STATUS_SUCCESS;
			}
		}
	}

	return STATUS_UNSUCCESSFUL;

}



void UninitializeSystemSource()
{

	__System = NULL;
	if (__NtoskrnlPath.Buffer != NULL && __NtoskrnlPath.Length != 0)
	{
		RtlFreeUnicodeString(&__NtoskrnlPath);
	}
	//x64栈回溯
#ifdef _WIN64
	if (__IsLoadImageNotifyRoutine == TRUE)
	{
		PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
		__IsLoadImageNotifyRoutine = FALSE;
	}
#endif // _WIN64

}