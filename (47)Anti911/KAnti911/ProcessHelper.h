#pragma once
#include <fltKernel.h>
#include "Common.h"
#include "IoControlRoutine.h"
#pragma region PROCESS

typedef struct _PROCESS_INFORMATIONEX_
{
	ULONG_PTR ProcessIdentity;
	ULONG_PTR ParentPid;
	PVOID EProcess;
	ULONGLONG CreateTime;
	WCHAR ProcessPath[MAX_PATH];
}PROCESS_INFORMATIONEX, * PPROCESS_INFORMATIONEX;


typedef struct _PROCESSES_INFORMATION_
{
	ULONG NumberOfProcess;
	PROCESS_INFORMATIONEX ProcessInfo[1];
}PROCESSES_INFORMATION, * PPROCESSES_INFORMATION;




#define PROCESS_TERMINATE                       0x0001
#define PROCESS_CREATE_THREAD                   0x0002
#define PROCESS_SET_SESSIONID                   0x0004
#define PROCESS_VM_OPERATION                    0x0008
#define PROCESS_VM_READ                         0x0010
#define PROCESS_VM_WRITE                        0x0020
#define PROCESS_CREATE_PROCESS                  0x0080
#define PROCESS_SET_QUOTA                       0x0100
#define PROCESS_SET_INFORMATION                 0x0200
#define PROCESS_QUERY_INFORMATION               0x0400
#define PROCESS_SUSPEND_RESUME                  0x0800
#define PROCESS_QUERY_LIMITED_INFORMATION       0x1000
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
#define PROCESS_ALL_ACCESS                      (STANDARD_RIGHTS_REQUIRED | \
                                                 SYNCHRONIZE | \
                                                 0xFFFF)
#else
#define PROCESS_ALL_ACCESS                      (STANDARD_RIGHTS_REQUIRED | \
                                                 SYNCHRONIZE | \
                                                 0xFFF)
#endif
#pragma endregion



#pragma region PEB
typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct RTL_DRIVE_LETTER_CURDIR
{
	USHORT              Flags;
	USHORT              Length;
	ULONG               TimeStamp;
	UNICODE_STRING      DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB_LDR_DATA32
{
	ULONG				Length;
	UCHAR				Initialized;
	UCHAR				_PADDING0_[0x3];
	ULONG				SsHandle;
	LIST_ENTRY32		InLoadOrderModuleList;
	LIST_ENTRY32		InMemoryOrderModuleList;
	LIST_ENTRY32		InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;



typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG               AllocationViewSize;
	ULONG               ViewSize;
	ULONG               Flags;
	ULONG               DebugFlags;
	HANDLE              ConsoleHandle;
	ULONG               ConsoleFlags;
	HANDLE              hStdInput;
	HANDLE              hStdOutput;
	HANDLE              hStdError;
	CURDIR              CurrentDirectory;
	UNICODE_STRING      DllPath;
	UNICODE_STRING      ImagePathName;
	UNICODE_STRING      CommandLine;
	PWSTR               Environment;
	ULONG               dwX;
	ULONG               dwY;
	ULONG               dwXViewSize;
	ULONG               dwYViewSize;
	ULONG               dwXCountChars;
	ULONG               dwYCountChars;
	ULONG               dwFillAttribute;
	ULONG               dwFlags;
	ULONG               wShowWindow;
	UNICODE_STRING      WindowTitle;
	UNICODE_STRING      Desktop;
	UNICODE_STRING      ShellInfo;
	UNICODE_STRING      RuntimeInfo;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;




typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;


typedef struct _PEB32
{
	
	UCHAR				InheritedAddressSpace;
	UCHAR				ReadImageFileExecOptions;
	UCHAR				BeingDebugged;
	UCHAR				BitField;
	ULONG				Mutant;
	ULONG				ImageBaseAddress;
	PPEB_LDR_DATA32				Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, * PPEB32;



typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32		InLoadOrderLinks;
	LIST_ENTRY32		InMemoryOrderLinks;
	LIST_ENTRY32		InInitializationOrderLinks;
	ULONG				DllBase;
	ULONG				EntryPoint;
	ULONG				SizeOfImage;
	UNICODE_STRING32	FullDllName;
	UNICODE_STRING32	BaseDllName;
	ULONG				Flags;
	USHORT				LoadCount;
	USHORT				TlsIndex;
	LIST_ENTRY32		HashLinks;
	ULONG				TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;
#pragma endregion


#pragma region MODULE
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;         // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageViewSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
#pragma endregion



//进程保护
typedef struct _COMMUNICATE_PROTECT_PROCESS_
{
	OPERATE_TYPE OperateType;

	int    NumberOfProcess;
	HANDLE ProcessIdentitys[MAX_PATH];

}COMMUNICATE_PROTECT_PROCESS, *PCOMMUNICATE_PROTECT_PROCESS;


typedef struct _PROTECT_PROCESS_INFORMATION
{
	int    NumberOfProcess;
	HANDLE ProcessIdentitys[MAX_PATH];
	FAST_MUTEX  FastMutex;
}PROTECT_PROCESS_INFORMATION,*PPROTECT_PROCESS_INFORMATION;



//进程隐藏
typedef struct _COMMUNICATE_HIDE_PROCESS_
{
	OPERATE_TYPE OperateType;
	HANDLE ProcessIdentity;

}COMMUNICATE_HIDE_PROCESS, * PCOMMUNICATE_HIDE_PROCESS;





#ifdef _WIN64
NTKERNELAPI
PVOID
NTAPI
PsGetCurrentProcessWow64Process();

NTKERNELAPI PVOID NTAPI PsGetCurrentProcessWow64Process();
#else
#endif

NTKERNELAPI PCHAR  NTAPI PsGetProcessImageFileName(PEPROCESS EProcess);


NTKERNELAPI
PPEB
NTAPI
PsGetProcessPeb(IN PEPROCESS Process);

NTKERNELAPI
NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation,
	ULONG ProcessInformationLength, PULONG ReturnLength);

NTKERNELAPI
HANDLE
NTAPI
PsGetProcessInheritedFromUniqueProcessId(
	IN PEPROCESS Process
);

/***************************************************************************************************************************/
void InitializeProcessSource();

PVOID GetUserModuleHandle(IN PEPROCESS EProcess, IN PUNICODE_STRING ModuleName);
BOOLEAN PsIsProcessTermination(PEPROCESS EProcess);
BOOLEAN PsIsRealProcess(PEPROCESS EProcess);
NTSTATUS PsLookupThreadByEProcess(PEPROCESS EProcess, PETHREAD* EThread);






BOOLEAN CheckNtdll32(ULONG VirtualAddress, PULONG DllBase);
BOOLEAN CheckNtdll64(ULONG_PTR VirtualAddress, PULONG_PTR DllBase);


NTSTATUS PsEnumProcess(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);
NTSTATUS PsEnumProcessInternal(PPROCESSES_INFORMATION ProcessesInfo, ULONG OutputBufferLength);
NTSTATUS PsProtectProcess(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);
NTSTATUS PsUnprotectProcess(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);
NTSTATUS PsClearProtectProcess(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);
NTSTATUS PsHideProcess(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);
VOID EnumProcessByService(PPROCESSES_INFORMATION ProcessesInfo, ULONG NumberOfProcess);
VOID EnumProcessByActiveLink(PPROCESSES_INFORMATION ProcessesInfo, ULONG NumberOfProcess);
VOID SetProcessInfoToList(PPROCESSES_INFORMATION ProcessesInfo, ULONG NumberOfProcess, PEPROCESS EProcess);

BOOLEAN IsProcessIdentifyExist(HANDLE ProcessIdentify);
BOOLEAN InsertProcessIdentify(HANDLE ProcessIdentify);
BOOLEAN RemoveProcessIdentify(HANDLE ProcessIdentify);
VOID ClearProcessIdentify();






