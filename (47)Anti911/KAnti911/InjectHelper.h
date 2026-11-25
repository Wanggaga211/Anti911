#pragma once
#include <fltKernel.h>
#include "Common.h"


//Ring3传递结构
typedef struct _INJECT_REQUEST_
{
	HANDLE ProcessIdentity;
	WCHAR  DllPath[MAX_PATH];
}INJECT_REQUEST, * PINJECT_REQUEST;



//Ring0注入数据
#define CALL_COMPLETE   0xC0371E7E
typedef struct _INJECT_BUFFER
{
	UCHAR ShellCode[0x200];
	UNICODE_STRING DllPath;
	wchar_t BufferData[260];
	PVOID ModuleHandle;
	ULONG Complete;      //0xC0371E7E
	NTSTATUS Status;     //ShellCode返回值
}INJECT_BUFFER, * PINJECT_BUFFER;
