#pragma once
#include <fltKernel.h>

void InitializeCallbackSouce(PDRIVER_OBJECT DriverObject);


NTSTATUS FileObjectCallback();
NTSTATUS ProcessObjectCallback();

OB_PREOP_CALLBACK_STATUS FileObjectPrevious(PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION ObPreviousOperationInfo);
OB_PREOP_CALLBACK_STATUS ProcessObjectPrevious(PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION ObPreviousOperationInfo);


void UninitializeCallbackSouce();