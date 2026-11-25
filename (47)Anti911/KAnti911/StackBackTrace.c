#include "StackBackTrace.h"
#include "ProcessHelper.h"



//栈回溯
#ifdef _WIN64
BOOLEAN __IsLoadImageNotifyRoutine = FALSE;
void  StackBackTrace()
{
	//注册一个模块加载的过滤函数
	NTSTATUS Status;
	Status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);   //函数指针
	if (NT_SUCCESS(Status))
		__IsLoadImageNotifyRoutine = TRUE;
}
VOID LoadImageNotifyRoutine(PUNICODE_STRING ImageName, HANDLE ProcessIdentity, PIMAGE_INFO ImageInfo)
{
	if (!(ImageInfo->SystemModeImage))   //Ring3层的一个程序加载一个模块
	{
		if (StackBackTraceInternal())
		{
			char* ImageName = PsGetProcessImageFileName(PsGetCurrentProcess());

			int v1 = 0;
		}
	}

}
BOOLEAN StackBackTraceInternal()
{
	__try
	{
		PVOID Callers[2 * MAX_STACK_DEPTH];
		ULONG FramesFound = RtlWalkFrameChain(Callers, FramesToCapture + FramesToSkip, USER_MODE_STACK);

		if (FramesFound <= FramesToSkip)
		{
			if (FramesFound == FramesToSkip)	// Process is initializing, log the first 2 or 3(WoW64) entries.
			{									// 1) Main binary								
				return TRUE;					// 2) Ntdll64
			}									// And optionally in case of WoW64 emulation
			return FALSE;						// 3) Ntdll32
		}										// During initialization RtlWalkFrameChain always returns only 1 frame so no need to verify if it's the Windows PE Loader
												// Because of this the list entry checks in both IsNtDll32 and IsNtDll64 could be removed

		for (ULONG i = FramesToSkip; i < FramesToCapture + FramesToSkip; i++)
		{
			if (i >= FramesFound)
				break;
			else if (!Callers[i])
				break;

			ULONG		Ntdll32;
			ULONG_PTR	Ntdll64;
			ULONG_PTR	Entry = ((ULONG_PTR)Callers[i]);

			if (PsGetCurrentProcessWow64Process())
			{
				if (CheckNtdll32((ULONG)Entry, &Ntdll32))
				{
					if (Ntdll32 != NULL)
					{

						return TRUE;
					}
				}
				// Could be the WoW64 subsystem loading or malicious DLL's getting injected/loaded
				else if (CheckNtdll64(Entry, &Ntdll64))
				{
				
					if(Ntdll64 !=NULL)
					{

						return TRUE;
					}
				}
			}
			else if (CheckNtdll64(Entry, &Ntdll64))
			{
				if (Ntdll64 != NULL)
				{

					return TRUE;
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
	return FALSE;
}

#endif // _WIN64
