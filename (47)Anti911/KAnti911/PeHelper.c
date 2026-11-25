#include "PeHelper.h"
PVOID GetProcAddress(IN PVOID ModuleBase, IN PCCHAR ServiceName)
{
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	PIMAGE_NT_HEADERS ImageNtHeaders = NULL;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = NULL;
	ULONG ViewSize = 0;
	ULONG_PTR ServiceAddress = 0;

	if (ModuleBase == NULL)
		return NULL;

	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}


	ImageNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + ImageDosHeader->e_lfanew);
	ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + 
		(ULONG_PTR)ModuleBase);


	ViewSize = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	PUSHORT AddressOfNameOrdinals = (PUSHORT)(ImageExportDirectory->AddressOfNameOrdinals + (ULONG_PTR)ModuleBase);
	PULONG  AddressOfNames = (PULONG)(ImageExportDirectory->AddressOfNames + (ULONG_PTR)ModuleBase);
	PULONG  AddressOfFunctions = (PULONG)(ImageExportDirectory->AddressOfFunctions + (ULONG_PTR)ModuleBase);

	for (ULONG i = 0; i < ImageExportDirectory->NumberOfFunctions; ++i)
	{
		USHORT Ordinals = 0xFFFF;
		PCHAR  v1 = NULL;


		if ((ULONG_PTR)ServiceName <= 0xFFFF)
		{
			Ordinals = (USHORT)i;
		}

		else if ((ULONG_PTR)ServiceName > 0xFFFF && i < ImageExportDirectory->NumberOfNames)
		{
			v1 = (PCHAR)(AddressOfNames[i] + (ULONG_PTR)ModuleBase);
			Ordinals = AddressOfNameOrdinals[i];
		}
		else
			return NULL;

		if (((ULONG_PTR)ServiceName <= 0xFFFF && (USHORT)((ULONG_PTR)ServiceName) == Ordinals + ImageExportDirectory->Base) ||
			((ULONG_PTR)ServiceName > 0xFFFF && strcmp(v1, ServiceName) == 0))
		{
			ServiceAddress = AddressOfFunctions[Ordinals] + (ULONG_PTR)ModuleBase;
			break;
		}
	}

	return (PVOID)ServiceAddress;
}

PVOID
RtlFindExportedRoutineByName(
	IN PVOID ModuleBase,
	IN PANSI_STRING ServiceName
)
{
	USHORT  v1;
	PULONG  AddressOfNames;
	PUSHORT AddressOfNameOrdinals;
	PULONG v2;
	LONG High;
	LONG Low;
	LONG Middle;
	LONG Result;
	ULONG ExportLength;
	PVOID FunctionAddress;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory;


	ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(
		ModuleBase,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_EXPORT,
		&ExportLength);

	if (ImageExportDirectory == NULL) {
		return NULL;
	}


	AddressOfNames = (PULONG)((PCHAR)ModuleBase + (ULONG)ImageExportDirectory->AddressOfNames);
	AddressOfNameOrdinals = (PUSHORT)((PCHAR)ModuleBase + (ULONG)ImageExportDirectory->AddressOfNameOrdinals);

	Low = 0;
	Middle = 0;
	High = ImageExportDirectory->NumberOfNames - 1;

	while (High >= Low) {

		Middle = (Low + High) >> 1;

		Result = strcmp(ServiceName->Buffer,
			(PCHAR)ModuleBase + AddressOfNames[Middle]);

		if (Result < 0) {
			High = Middle - 1;
		}
		else if (Result > 0) {
			Low = Middle + 1;
		}
		else {
			break;
		}
	}
	if (High < Low) {
		return NULL;
	}

	v1 = AddressOfNameOrdinals[Middle];


	if ((ULONG)v1 >= ImageExportDirectory->NumberOfFunctions) {
		return NULL;
	}


	v2 = (PULONG)((PCHAR)ModuleBase + (ULONG)ImageExportDirectory->AddressOfFunctions);

	FunctionAddress = (PVOID)((PCHAR)ModuleBase + v2[v1]);

	return FunctionAddress;
}
