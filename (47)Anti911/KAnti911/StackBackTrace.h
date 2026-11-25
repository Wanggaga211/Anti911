#pragma once
#include <fltKernel.h>



#ifdef _WIN64
#define KERNEL_MODE_STACK	0
#define USER_MODE_STACK		1
#define FramesToSkip		1
#define FramesToCapture		16
#define MAX_STACK_DEPTH		32
extern BOOLEAN __IsLoadImageNotifyRoutine;
void  StackBackTrace();
VOID LoadImageNotifyRoutine(PUNICODE_STRING ImageName, HANDLE ProcessIdentity, PIMAGE_INFO ImageInfo);
BOOLEAN StackBackTraceInternal();
#else
#endif // _WIN64
