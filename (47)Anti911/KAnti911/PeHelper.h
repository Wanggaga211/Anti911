#pragma once
#include <fltKernel.h>
#include <ntimage.h>

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(PVOID Base);


NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
	IN PVOID Base,
	IN BOOLEAN MappedAsImage,
	IN USHORT DirectoryEntry,
	OUT PULONG ViewSize
);


PVOID GetProcAddress(IN PVOID ModuleBase, IN PCCHAR ServiceName);

PVOID
RtlFindExportedRoutineByName(
	IN PVOID ModuleBase,
	IN PANSI_STRING ServiceName
);

