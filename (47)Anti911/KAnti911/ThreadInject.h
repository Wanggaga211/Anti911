#pragma once
#include <fltKernel.h>
#include "InjectHelper.h"
#include "ProcessThread.h"
NTSTATUS ThreadInject(IN INJECT_REQUEST InjectRequest);



NTSTATUS CreateThread(
	IN PVOID BaseAddress,
	IN PVOID ParameterData,
	IN ULONG Flags,
	IN BOOLEAN IsWait,
	OUT PNTSTATUS ExitStatus);
NTSTATUS
NTAPI
CreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,	//目标进程句柄
	IN PVOID StartAddress,	//线程起始地址
	IN PVOID ParameterData,		//线程参数
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T ViewSizeOfStackCommit,
	IN SIZE_T ViewSizeOfStackReserve,
	IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList);


