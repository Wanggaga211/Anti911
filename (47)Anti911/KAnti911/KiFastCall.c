#include "KiFastCall.h"
#include "HookHelper.h"
#include "SystemHelper.h"
#include "MemoryHelper.h"
#include <ntimage.h>
#include "Common.h"
#include "PeHelper.h"
#include "ShellCode.h"
#include "StringHelper.h"
#include "SsdtHook.h"
#include "FakeService.h"



SYSTEM_SERVICE_DESCRIPTOR_TABLE __FakeKeServiceDescriptorTable;
#ifdef _WIN64
#else
ULONG_PTR __GoBack = 0;
PVOID ReloadNtoskrnl(PUNICODE_STRING NtoskrnlPath, PVOID ImageBase)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	OBJECT_ATTRIBUTES ObjectAttributes;

	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatusBlock;

	FILE_STANDARD_INFORMATION FileStandardInfo;
	PVOID VirtualAddress, v5;
	LARGE_INTEGER ReturnLength = { 0 };

	InitializeObjectAttributes(&ObjectAttributes, NtoskrnlPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = ZwCreateFile(&FileHandle, FILE_READ_DATA, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, \
		FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(Status))
	{
		return NULL;
	}
	//根据文件句柄获得文件大小
	Status = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &FileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), \
		FileStandardInformation);
	if (!NT_SUCCESS(Status))
	{

		ZwClose(FileHandle);
		return NULL;
	}

	VirtualAddress = AllocatePoolWithTag(PagedPool, FileStandardInfo.EndOfFile.LowPart);
	if (NULL == VirtualAddress)
	{

		ZwClose(FileHandle);
		return NULL;
	}

	Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, VirtualAddress, FileStandardInfo.EndOfFile.LowPart, \
		& ReturnLength, NULL);
	if (!NT_SUCCESS(Status))
	{

		FreePoolWithTag(VirtualAddress);
		ZwClose(FileHandle);
		return NULL;
	}
	ZwClose(FileHandle);

	v5 = ReloadNtoskrnlInternal(VirtualAddress, ImageBase);
	if (NULL == v5)
	{

		FreePoolWithTag(VirtualAddress);
		return NULL;
	}
	FreePoolWithTag(VirtualAddress);

	return v5;
}
PVOID ReloadNtoskrnlInternal(unsigned char* VirtualAddress, PVOID ImageBase)
{
	PIMAGE_DOS_HEADER ImageDosHeader;
	PIMAGE_NT_HEADERS ImageNtHeaders;

	ULONG v7;
	unsigned char* v5;

	PIMAGE_SECTION_HEADER ImageSectionHeader;

	int i;

	ImageDosHeader = (PIMAGE_DOS_HEADER)VirtualAddress;
	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}
	ImageNtHeaders = (PIMAGE_NT_HEADERS)(VirtualAddress + ImageDosHeader->e_lfanew);
	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	v7 = ALIGN_SIZE(ImageNtHeaders->OptionalHeader.SizeOfImage, ImageNtHeaders->OptionalHeader.SectionAlignment);  //内存粒度对齐后的镜像大小
	v5 = AllocatePoolWithTag(NonPagedPool, v7);  //内存粒度
	if (NULL == v5)
	{
		return NULL;
	}

	RtlZeroMemory(v5, v7);
	RtlCopyMemory(v5, VirtualAddress, ImageNtHeaders->OptionalHeader.SizeOfHeaders);   //拷贝所有头部


	ImageSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG)ImageNtHeaders + sizeof(ImageNtHeaders->Signature) + \
		sizeof(ImageNtHeaders->FileHeader) + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);

	for (i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; i++)
	{
		RtlCopyMemory(v5 + ImageSectionHeader[i].VirtualAddress, \
			VirtualAddress + ImageSectionHeader[i].PointerToRawData, ImageSectionHeader[i].Misc.VirtualSize);
	}


	FixImportDescriptor(v5);
	FixBaseRelocation(v5, ImageBase);

	return v5;
}
VOID FixImportDescriptor(IN PVOID VirtualAddress)
{
	PIMAGE_IMPORT_DESCRIPTOR ImpageImportDescriptor;
	ULONG ImportLength;

	PIMAGE_THUNK_DATA OriginalFirstThunk, FirstThunk;

	ImpageImportDescriptor = RtlImageDirectoryEntryToData(VirtualAddress, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ImportLength);
	while (ImpageImportDescriptor->OriginalFirstThunk && ImpageImportDescriptor->Name)
	{
		PVOID ModuleBase;
		//通过导入模块的名称获取系统中正在使用的模块地址
		ModuleBase = GetModuleHandle((PUCHAR)VirtualAddress + ImpageImportDescriptor->Name);
		if (ModuleBase == NULL)
		{

			break;
		}

		//修复自己
		OriginalFirstThunk = (PIMAGE_THUNK_DATA)((ULONG)VirtualAddress + ImpageImportDescriptor->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((ULONG)VirtualAddress + ImpageImportDescriptor->FirstThunk);
		while (OriginalFirstThunk->u1.Ordinal)
		{
			PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)VirtualAddress + OriginalFirstThunk->u1.AddressOfData);
			//序号导入
			if (IMAGE_SNAP_BY_ORDINAL32(OriginalFirstThunk->u1.Ordinal))
			{
				//内核中貌似没有序号导出的

			}
			else
			{
				ANSI_STRING Name;
				RtlInitAnsiString(&Name, ImageImportByName->Name);
				//修复我们重载的模块的导入函数地址
				FirstThunk->u1.Function = (ULONG)RtlFindExportedRoutineByName(ModuleBase, &Name);
			}
			OriginalFirstThunk++;
			FirstThunk++;
		}
		ImpageImportDescriptor++;
	}
	return;
}
VOID FixBaseRelocation(IN PVOID VirtualAddress, IN PVOID ImageBase)
{
	PIMAGE_BASE_RELOCATION ImageBaseRelocation;
	ULONG ViewSize;
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)VirtualAddress;
	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageDosHeader->e_lfanew + (ULONG)VirtualAddress);


	ImageBaseRelocation = RtlImageDirectoryEntryToData(VirtualAddress, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &ViewSize);
	if (NULL == ImageBaseRelocation)
	{

		return;
	}
	do
	{
		ULONG ItemCount;
		ULONG i;
		USHORT TypeOffset;
		ULONG RelocationAddress;

		ItemCount = (ImageBaseRelocation->SizeOfBlock - 8) / 2;
		for (i = 0; i < ItemCount; i++)
		{

			TypeOffset = ((PUSHORT)((ULONG)ImageBaseRelocation + 8))[i];
			if (TypeOffset >> 12 == IMAGE_REL_BASED_HIGHLOW)
			{
				RelocationAddress = ImageBaseRelocation->VirtualAddress + (TypeOffset & 0x0FFF) + (ULONG)VirtualAddress;
				if (ImageBase == NULL)
				{
					*(PULONG)RelocationAddress = *(PULONG)RelocationAddress + (ULONG)VirtualAddress - ImageNtHeaders->OptionalHeader.ImageBase;
				}
				else
				{
					*(PULONG)RelocationAddress = *(PULONG)RelocationAddress + (ULONG)ImageBase - ImageNtHeaders->OptionalHeader.ImageBase;
				}
			}
		}
		ImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG)ImageBaseRelocation + ImageBaseRelocation->SizeOfBlock);

	} while (ImageBaseRelocation->VirtualAddress);  //第一个VirtualAddress可能是0

}
PVOID FixFakeKiServiceTable(IN PVOID VirtualAddress, IN PVOID ImageBase)
{
	PIMAGE_BASE_RELOCATION ImageBaseRelocation;
	ULONG RelocLength;
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)VirtualAddress;
	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageDosHeader->e_lfanew + (ULONG)VirtualAddress);

	ImageBaseRelocation = RtlImageDirectoryEntryToData(VirtualAddress, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &RelocLength);
	if (NULL == ImageBaseRelocation)
	{
		return NULL;
	}
	do
	{
		ULONG ItemCount;
		ULONG i;
		USHORT TypeOffset;
		ULONG RelocationAddress;

		ItemCount = (ImageBaseRelocation->SizeOfBlock - 8) / 2;
		for (i = 0; i < ItemCount; i++)
		{
			TypeOffset = ((PUSHORT)((ULONG)ImageBaseRelocation + 8))[i];
			if (TypeOffset >> 12 == IMAGE_REL_BASED_HIGHLOW)
			{
				RelocationAddress = ImageBaseRelocation->VirtualAddress + (TypeOffset & 0x0FFF) + (ULONG)VirtualAddress;
				if (*(PULONG)RelocationAddress == (ULONG)(KeServiceDescriptorTable))
				{



					// mov ds:_KeServiceDescriptorTable, offset _KiServiceTable

					//8a6a9c1f c705005b9a843ca48b84 mov dword ptr[nt!KeServiceDescriptorTable(849a5b00)], offset nt!KiServiceTable(848ba43c)
					if (*(PUSHORT)(RelocationAddress - 2) == 0x05C7)
					{
						ULONG j;
						PULONG FakeKiServiceBase;

						FakeKiServiceBase = (PULONG)(*(PULONG)(RelocationAddress + 4) - (ULONG)ImageBase + (ULONG)VirtualAddress);

						/*
						0: kd> dd 8a6a9c21+4
						ReadVirtual: 8a6a9c9f not properly sign extended
						8a6a9c25  848ba43c
						*/


						for (j = 0; j < KeServiceDescriptorTable->NumberOfServices; j++)
						{
							FakeKiServiceBase[j] = (ULONG)(KeServiceDescriptorTable->ServiceTableBase[j]) - \
								(ULONG)ImageBase + (ULONG)VirtualAddress;
						}
						__FakeKeServiceDescriptorTable.ServiceTableBase = FakeKiServiceBase;
						__FakeKeServiceDescriptorTable.NumberOfServices = KeServiceDescriptorTable->NumberOfServices;
						__FakeKeServiceDescriptorTable.ServiceTableBase = KeServiceDescriptorTable->ServiceTableBase;
						__FakeKeServiceDescriptorTable.ServiceCounterTableBase = KeServiceDescriptorTable->ServiceCounterTableBase;
						return NULL;
					}
				}
			}
		}
		ImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG)ImageBaseRelocation + ImageBaseRelocation->SizeOfBlock);
	} while (ImageBaseRelocation->VirtualAddress);
	return NULL;
}
VOID __declspec(naked) FakeKiFastCallEntry()
{
	_asm
	{

		pushad      //PUSHAD指令压入32位寄存器，其入栈顺序是:EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI
		pushfd

		push  edx
		push  eax
		push  edi
		call  FilterService
		//再返回前修改堆栈里的数据
		/*
		Flag   0
		edi    4
		esi    8
		ebp    12
		esp    16
		ebx    20
		edx ---->函数地址 24
		ecx
		eax
		*/

		mov[esp + 0x18], eax
		popfd
		popad

		sub     esp, ecx
		shr     ecx, 2
		jmp   __GoBack
	}
}
BOOLEAN KiFastCallHook(HOOKS* Hooks, PVOID* FakeNtoskrnl)
{
	PVOID KiFastCallEntry;
	BOOLEAN IsAlreadyHook = FALSE;
	int i = 0;
	ULONG_PTR OriginalAddress;

	PMDL Mdl = NULL;
	PVOID  VirtualAddress = NULL;
	NTSTATUS Status;
	HOOKS* v1 = (HOOKS*)Hooks;
	KIRQL Irql;
	PVOID  Ntoskrnl = NULL;
	PVOID  v5 = NULL; //内存粒度对齐的Ntos模块地址
	ULONG  ImageViewSize = 0;
	UNICODE_STRING NtoskrnlPath = { 0 };
	if (__Ntoskrnl == 0)
	{
		Ntoskrnl = GetNtoskrnlInfo(&NtoskrnlPath, &ImageViewSize);   //获得原始模块地址
	}

	if (Ntoskrnl == NULL || NtoskrnlPath.Buffer == NULL)
	{
		return;
	}

	v5 = ReloadNtoskrnl(&NtoskrnlPath, Ntoskrnl);

	FixFakeKiServiceTable(v5, Ntoskrnl);   //构建伪Ssdt


	KiFastCallEntry = GetKiFastCallEntry();
	/*
	kd> rdmsr 0x176
	msr[176] = 00000000`83e450c0

	8487985e 64ff05b0060000  inc     dword ptr fs:[6B0h]
	84879865 8bf2            mov     esi,edx
	84879867 33c9            xor     ecx,ecx
	84879869 8b570c          mov     edx,dword ptr [edi+0Ch]
	8487986c 8b3f            mov     edi,dword ptr [edi]
	8487986e 8a0c10          mov     cl,byte ptr [eax+edx]
	84879871 8b1487          mov     edx,dword ptr [edi+eax*4]   //Ring3调用的Ssdt服务地址从Ssdt表中获取到了
	84879874 2be1            sub     esp,ecx
	84879876 c1e902          shr     ecx,2
	84879879 8bfc            mov     edi,esp
	8487987b f6457202        test    byte ptr [ebp+72h],2

	*/
	if (KiFastCallEntry == NULL)
	{

		goto Exit;
	}
	OriginalAddress = SearchPattern1("\x2B\xE1\xC1\xE9\x02\x8B\xFC", 7, (PCHAR)KiFastCallEntry, 0x1000);

	if (OriginalAddress == NULL)
	{
		goto Exit;
	}

	for (i = 0; i < v1->MaxHooks; i++)
	{
		if (v1->HookEntry[i].IsAlreadyHook == 0)
		{

			break;
		}

	}
	if (i == v1->MaxHooks)
	{
		goto Exit;
	}



	Status = VirtualProtect(&Mdl, OriginalAddress,
		0x1000, &VirtualAddress);


	//Irql = KeRaiseIrqlToDpcLevel();
	//CloseWriteProtect();
	*(PUCHAR)OriginalAddress = 0xE9;
	*(PULONG)(OriginalAddress + 1) = (ULONG)FakeKiFastCallEntry - OriginalAddress - 5;
	v1->HookEntry[i].CodeLength = 7;
	memcpy(v1->HookEntry[i].OriginalCode, "\x2B\xE1\xC1\xE9\x02\x8B\xFC", v1->HookEntry[i].CodeLength);
	v1->HookEntry[i].u1.OriginalAddress = OriginalAddress;
	__GoBack = OriginalAddress;
	__GoBack += 5;
	UnvirtualProtect(Mdl, VirtualAddress);

	//OpenWriteProtect();

	//KeLowerIrql(Irql);
	IsAlreadyHook = TRUE;
	v1->HookEntry[i].IsAlreadyHook = TRUE;
	v1->HookEntry[i].IsKiFastCallHook = TRUE;

	*FakeNtoskrnl = v5;
	return IsAlreadyHook;

Exit:
	if (NULL == v5)
	{

		FreePoolWithTag(v5);

	}

	return IsAlreadyHook;
}

BOOLEAN GetKiFastCall()
{
	HANDLE EventHandle = (HANDLE)0x12345678;
	HOOK_ENREY* HookEntry = NULL;
	PUCHAR SearchAddress = NULL;
	int i = 0;
	KIRQL Irql;
	if (SsdtHook(__Hooks, "ZwSetEvent", FakeSetEvent, 2)==FALSE)
	{
		return FALSE;
	}

	HookEntry = GetAlreadyHookEntry(__Hooks, "ZwSetEvent");

	if (HookEntry == NULL)
	{
		//恢复Hook
		return FALSE;
	}
	__OriginalSetEvent = HookEntry->u1.OriginalOffset;
	ZwSetEvent(&EventHandle, NULL);  

	

	SearchAddress = (PVOID)__KiFastCallEntryRetAddress;

	while (1)
	{
	
		if (memcmp(SearchAddress, "\x2b\xe1\xc1\xe9\x02", 5) == 0)
		{

			int v1 = 0;
			break;
		}

		SearchAddress--;
	}

	Irql = KeRaiseIrqlToDpcLevel();
	if (HookEntry->IsAlreadyHook == TRUE)
	{
		UnssdtHook(__Hooks, "ZwSetEvent");

	}
	KeLowerIrql(Irql);
}




#endif // __WIN64






