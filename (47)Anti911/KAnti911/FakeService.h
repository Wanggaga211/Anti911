#pragma once
#include <fltKernel.h>

typedef  NTSTATUS (NTAPI* LPFN_TERMINATEPROCESS)(_In_opt_ HANDLE hProcess,IN NTSTATUS uExitCode);
typedef
NTSTATUS
(__stdcall* LPFN_NTSETEVENT)(IN PHANDLE EventHandle,
	OUT PLONG PreviousState OPTIONAL);


ULONG_PTR __stdcall FilterService(ULONG_PTR ServiceTableBase, ULONG ServiceIndex, ULONG_PTR ServiceAddress);


NTSTATUS
NTAPI
FakeTerminateProcess(
	_In_opt_ HANDLE ProcessHandle,
	_In_ NTSTATUS ExitStatus);


#ifdef _WIN64
#else

//Õ»»ØËÝ
extern LPFN_NTSETEVENT __OriginalSetEvent;
extern PUCHAR	__KiFastCallEntryRetAddress;

NTSTATUS NTAPI FakeSetEvent(IN PHANDLE EventHandle, OUT PLONG PreviousState OPTIONAL);
#endif // _WIN64




