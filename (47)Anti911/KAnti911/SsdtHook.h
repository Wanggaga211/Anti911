#pragma once
#include <fltKernel.h>
#include "HookHelper.h"

BOOLEAN SsdtHook(HOOKS* Hooks, char* ServiceName, ULONG_PTR FakeAddress, ULONG ParameterCount);
BOOLEAN UnssdtHook(HOOKS* Hooks, char* ServiceName);