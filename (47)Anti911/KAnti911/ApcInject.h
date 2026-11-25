#pragma once
#include <fltKernel.h>
#include "InjectHelper.h"
#include "ProcessHelper.h"
#include "ProcessThread.h"
#include "IoControlRoutine.h"

typedef struct _COMMUNICATE_APC_INJECT_
{
	OPERATE_TYPE OperateType;

	ULONG_PTR ProcessIdentity;
	WCHAR  DllPath[MAX_PATH];

}COMMUNICATE_APC_INJECT, * PCOMMUNICATE_APC_INJECT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID(NTAPI* PKKERNEL_ROUTINE)(
	PRKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
	);


typedef VOID
(NTAPI* PKRUNDOWN_ROUTINE)(
	IN struct _KAPC* Apc);


NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
	IN PKAPC Apc,
	IN PKTHREAD Thread,
	IN KAPC_ENVIRONMENT ApcStateIndex,
	IN PKKERNEL_ROUTINE KernelRoutine,
	IN PKRUNDOWN_ROUTINE RundownRoutine,
	IN PKNORMAL_ROUTINE NormalRoutine,
	IN KPROCESSOR_MODE ApcMode,
	IN PVOID NormalContext
);

NTKERNELAPI
BOOLEAN
NTAPI
KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);
NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
	PKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment
);



NTSTATUS ApcInject(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);
NTSTATUS ExecuteApc(PINJECT_BUFFER VirtualAddress, PEPROCESS EProcess);
NTSTATUS QueueUserApc(PETHREAD EThread, PVOID CallbackRoutine, PVOID ParameterData1, PVOID ParameterData2, PVOID ParameterData3, BOOLEAN IsOk);
VOID KernelApcKernelCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);
VOID KernelApcUserCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);