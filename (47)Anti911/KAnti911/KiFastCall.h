#pragma once
#include <fltKernel.h>
#include "HookHelper.h"
#include "SystemHelper.h"
VOID InstallKiFastCallHook();
BOOLEAN KiFastCallHook(HOOKS* Hooks, PVOID* FakeNtoskrnl);
#ifdef  _WIN64
#else

PVOID ReloadNtoskrnl(PUNICODE_STRING NtoskrnlPath, PVOID ImageBase);
PVOID ReloadNtoskrnlInternal(unsigned char* VirtualAddress, PVOID ImageBase);
VOID  FixImportDescriptor(IN PVOID VirtualAddress);
VOID  FixBaseRelocation(IN PVOID VirtualAddress, IN PVOID ImageBase);
PVOID FixFakeKiServiceTable(IN PVOID VirtualAddress, IN PVOID ImageBase);


BOOLEAN GetKiFastCall();

#endif //  _WIN64



extern SYSTEM_SERVICE_DESCRIPTOR_TABLE __FakeKeServiceDescriptorTable;