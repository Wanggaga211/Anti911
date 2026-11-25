#pragma once
#include <fltKernel.h>
#include "InjectHelper.h"
#include "FakeService.h"

PVOID GetKiFastCallEntry();


PINJECT_BUFFER GetNativeLoadCode1(IN PVOID LdrLoadDll, IN PUNICODE_STRING DllPath, IN SIZE_T ViewSize);
PINJECT_BUFFER GetNativeUnloadCode1(PVOID ModuleHandle, IN PVOID LdrUnloadDll, IN SIZE_T ViewSize);
PINJECT_BUFFER GetWow64LoadCode1(IN PVOID LdrLoadDll, IN PUNICODE_STRING DllPath, IN SIZE_T ViewSize);
PINJECT_BUFFER GetWow64UnloadCode1(IN PVOID ModuleHandle, IN PVOID LdrUnloadDll, IN SIZE_T ViewSize);


PINJECT_BUFFER GetWow64LoadCode2(IN PVOID LdrLoadDll, IN PUNICODE_STRING DllPath, IN SIZE_T ViewSize);
PINJECT_BUFFER GetWow64UnloadCode2(IN PVOID ModuleHandle, IN PVOID LdrUnloadDll, IN SIZE_T ViewSize);
PINJECT_BUFFER GetNativeLoadCode2(IN PVOID LdrLoadDll, IN PUNICODE_STRING DllPath, IN SIZE_T ViewSize);
PINJECT_BUFFER GetNativeUnloadCode2(IN PVOID ModuleHandle, IN PVOID LdrUnloadDll, IN SIZE_T ViewSize);