#include "ApcInject.h"
#include "ProcessHelper.h"
#include "PeHelper.h"
#include "ShellCode.h"


NTSTATUS ApcInject(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{
	PEPROCESS EProcess = NULL;
	KAPC_STATE ApcState;
	NTSTATUS Status = STATUS_SUCCESS;
	PVOID    ModuleHandle = NULL;
	SIZE_T ViewSize = PAGE_SIZE;
	UNICODE_STRING DllPath = { 0 };
	WCHAR v2[MAX_PATH] = { 0 };

	PCOMMUNICATE_APC_INJECT v10 = (PCOMMUNICATE_APC_INJECT)InputBuffer;
	ULONG_PTR ProcessIdentity;
	

	if (!InputBuffer ||
		InputBufferLength != sizeof(COMMUNICATE_APC_INJECT))
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (v10->ProcessIdentity == NULL)
	{
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}
	//Unicode字符集 TCHAR为双字

	wcscpy(v2, v10->DllPath);
	RtlInitUnicodeString(&DllPath,v2);//Ring3层传下来的Dll
	ProcessIdentity = v10->ProcessIdentity;
	//通过进程Identity获得进程对象
	Status = PsLookupProcessByProcessId(ProcessIdentity, &EProcess);
	if (Status != STATUS_SUCCESS)
	{
		DbgPrint(("PsLookupProcessByProcessId函数失败\n"));
		return Status;
	}
	//KeStackAttachProcess例程  将当前线程连接到目标进程的地址空间。
	KeStackAttachProcess((PRKPROCESS)EProcess, &ApcState);
	__try
	{
		PVOID ModuleBase = NULL;
		PVOID LdrLoadDll = NULL;
		PVOID LdrUnloadDll = NULL;
		UNICODE_STRING v1 = { 0 };
	

		//获取ntdll模块基地址
		RtlInitUnicodeString(&v1, L"Ntdll.dll");
		ModuleBase = GetUserModuleHandle(EProcess, &v1);   //目标Ring3进程空间获取Ntdll模块基地址
		if (!ModuleBase)
		{

			Status = STATUS_NOT_FOUND;
		}

		//获取LdrLoadDll
		if (NT_SUCCESS(Status))
		{
			LdrLoadDll = GetProcAddress(ModuleBase, "LdrLoadDll");
			LdrUnloadDll = GetProcAddress(ModuleBase, "LdrUnloadDll");
			if (!LdrLoadDll || !LdrUnloadDll)
			{
				Status = STATUS_NOT_FOUND;
			}
		}
	

		//构建感染代码

#ifdef  _WIN64

		PINJECT_BUFFER v5 = GetNativeLoadCode2(LdrLoadDll, &DllPath, ViewSize);

#else 
		PINJECT_BUFFER v5 = GetWow64LoadCode2(LdrLoadDll, &DllPath, ViewSize);
#endif //  _WIN64


		Status = ExecuteApc(v5, EProcess);


		if (!NT_SUCCESS(Status))
		{
			DbgPrint(("ExecuteApc函数失败\n"));
		}
		if (v5->Complete != CALL_COMPLETE)
		{
			DbgPrint(("ShellCode执行失败\n"));

		}
		ModuleHandle = v5->ModuleHandle;
		if (v5 != NULL)
		{
			ViewSize = PAGE_SIZE;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &v5, &ViewSize, MEM_RELEASE);
		}
#ifdef  _WIN64

		v5 = GetNativeUnloadCode2(ModuleHandle, LdrUnloadDll, ViewSize);

#else 
		v5 = GetWow64UnloadCode2(ModuleHandle, LdrUnloadDll, ViewSize);
#endif //  _WIN64

		Status = ExecuteApc(v5, EProcess);




		if (v5 != NULL)
		{
			ViewSize = PAGE_SIZE;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &v5, &ViewSize, MEM_RELEASE);
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

		Status = STATUS_UNSUCCESSFUL;
	}
	//将当前线程返回原进程的地址空间。
	KeUnstackDetachProcess(&ApcState);
	//释放EProcess
	ObDereferenceObject(EProcess);
	return Status;
}
NTSTATUS ExecuteApc(PINJECT_BUFFER VirtualAddress, PEPROCESS EProcess)
{

	//进程中的所有线程都会有一个apc队列
	//thread    thread    thread
	NTSTATUS Status = STATUS_SUCCESS;
	PETHREAD EThread = NULL;

	//获得合适的线程
	Status = PsLookupThreadByEProcess(EProcess, &EThread);  //得到一个活跃的线程

	if (NT_SUCCESS(Status))
	{
		//把执行的函数地址放入到该线程的apc队列中



		Status = QueueUserApc(EThread, VirtualAddress->ShellCode, NULL, NULL, NULL, TRUE);
		//等待完成
		if (NT_SUCCESS(Status))
		{
			LARGE_INTEGER Interval = { 0 };
			Interval.QuadPart = -(5LL * 10 * 1000);

			for (ULONG i = 0; i < 10000; i++)
			{
				//进程是否还存在
				if (PsIsProcessTermination(PsGetCurrentProcess()) || PsIsThreadTerminating(EThread))
				{
					Status = STATUS_PROCESS_IS_TERMINATING;
					break;
				}

				if (VirtualAddress->Complete == CALL_COMPLETE)
				{


					break;
				}


				if (!NT_SUCCESS(Status = KeDelayExecutionThread(KernelMode, FALSE, &Interval)))
				{
					break;
				}

			}

			if (NT_SUCCESS(Status))
			{
				Status = VirtualAddress->Status;
			}
			else
			{
			}


		}
	}
	else
	{
	}


	if (EThread)
	{
		ObDereferenceObject(EThread);
	}


	return Status;
}
NTSTATUS QueueUserApc(PETHREAD EThread, PVOID CallbackRoutine, PVOID ParameterData1, PVOID ParameterData2, PVOID ParameterData3, BOOLEAN IsForce)
{
	ASSERT(EThread != NULL);
	if (EThread == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}


	//申请APC
	PKAPC v1 = NULL;
	PKAPC v2 = ExAllocatePool(NonPagedPool, sizeof(KAPC));   //申请一个APC结构

	if (v2 == NULL)
	{
		return STATUS_NO_MEMORY;
	}

	//初始化APC
	KeInitializeApc(
		v2, (PKTHREAD)EThread,
		OriginalApcEnvironment, &KernelApcUserCallback,
		NULL, (PKNORMAL_ROUTINE)(ULONG_PTR)CallbackRoutine, UserMode, ParameterData1
	);
	if (IsForce)
	{
		v1 = ExAllocatePool(NonPagedPool, sizeof(KAPC));
		KeInitializeApc(
			v1, (PKTHREAD)EThread,
			OriginalApcEnvironment, &KernelApcKernelCallback,    //析构函数
			NULL, NULL, KernelMode, NULL
		);
	}

	//插入APC队列
	if (KeInsertQueueApc(v2, ParameterData2, ParameterData3, 0))
	{
		if (IsForce && v1)
		{
			KeInsertQueueApc(v1, NULL, NULL, 0);
		}


		return STATUS_SUCCESS;
	}
	else
	{

		ExFreePool(v2);

		if (v1)
		{
			ExFreePool(v1);
		}
		return STATUS_NOT_CAPABLE;
	}
}
VOID KernelApcKernelCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	KeTestAlertThread(UserMode);      //可提醒
	ExFreePool(Apc);
}

VOID KernelApcUserCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	if (PsIsThreadTerminating(PsGetCurrentThread()))
	{
		*NormalRoutine = NULL;
	}

#ifdef  _WIN64
	if (PsGetCurrentProcessWow64Process() != NULL)
		PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);
#endif //  _WIN64


	ExFreePool(Apc);
}