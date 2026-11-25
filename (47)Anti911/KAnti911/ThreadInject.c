#include "ThreadInject.h"
#include "InjectHelper.h"
#include "ProcessHelper.h"
#include "ProcessThread.h"
#include "PeHelper.h"
#include "ShellCode.h"
#include "SystemHelper.h"


NTSTATUS ThreadInject(IN INJECT_REQUEST InjectRequest)
{
	PEPROCESS EProcess = NULL;
	KAPC_STATE ApcState;
	NTSTATUS Status = STATUS_SUCCESS;
	SIZE_T ViewSize = PAGE_SIZE;
	PVOID ModuleHandle = NULL;
	if (InjectRequest.ProcessIdentity == NULL)
	{
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}
	//获取EProcess
	Status = PsLookupProcessByProcessId(InjectRequest.ProcessIdentity, &EProcess);
	if (Status != STATUS_SUCCESS)
	{
		DbgPrint(("PsLookupProcessByProcessId函数失败\n"));
		return Status;
	}
	//KeStackAttachProcess例程  将当前线程连接到目标进程的地址空间。
	KeStackAttachProcess((PRKPROCESS)EProcess, &ApcState);
	__try
	{
		PVOID Ntdll = NULL;
		PVOID LdrLoadDll = NULL;
		PVOID LdrUnloadDll = NULL;
		UNICODE_STRING v1 = { 0 };
		UNICODE_STRING DllPath = { 0 };

		//获取ntdll模块基地址
		RtlInitUnicodeString(&v1, L"Ntdll.dll");
		Ntdll = GetUserModuleHandle(EProcess, &v1);
		if (!Ntdll)
		{

			Status = STATUS_NOT_FOUND;
		}

		//获取LdrLoadDll
		if (NT_SUCCESS(Status))
		{
			LdrLoadDll = GetProcAddress(Ntdll, "LdrLoadDll");
			LdrUnloadDll = GetProcAddress(Ntdll, "LdrUnloadDll");
			if (!LdrLoadDll || !LdrUnloadDll)
			{
				Status = STATUS_NOT_FOUND;
			}
		}
		//Unicode字符集 TCHAR为双字
		RtlInitUnicodeString(&DllPath, InjectRequest.DllPath);

		//构建感染代码

#ifdef  _WIN64

		PINJECT_BUFFER v5 = GetNativeLoadCode1(LdrLoadDll, &DllPath, ViewSize);

#else 
		PINJECT_BUFFER v5 = GetWow64LoadCode1(LdrLoadDll, &DllPath, ViewSize);
#endif //  _WIN64



#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER      0x00000004

		//启动一个内存线程
		CreateThread(v5, CALL_COMPLETE, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, TRUE, &Status);

		if (!NT_SUCCESS(Status))
		{
			DbgPrint(("ExecuteInNewThread函数失败\n"));
		}
		if (v5->Complete != CALL_COMPLETE)
		{
			DbgPrint(("ShellCode执行失败\n"));

		}
		if (v5 != NULL)
		{
			ModuleHandle = v5->ModuleHandle;
			ViewSize = PAGE_SIZE;
			ZwFreeVirtualMemory(ZwCurrentProcess(), &v5, &ViewSize, MEM_RELEASE);
		}
#ifdef  _WIN64

		v5 = GetNativeUnloadCode1(ModuleHandle, LdrUnloadDll, ViewSize);

#else 
		v5 = GetWow64UnloadCode1(ModuleHandle, LdrUnloadDll, ViewSize);
#endif //  _WIN64


		CreateThread(v5, CALL_COMPLETE, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, TRUE, &Status);

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


NTSTATUS CreateThread(
	IN PVOID ThreadProcedure,
	IN PVOID ParameterData,
	IN ULONG Flags,
	IN BOOLEAN IsWait,
	OUT PNTSTATUS ExitStatus
)
{
	HANDLE ThreadHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	//指定一个对象句柄的属性  句柄只能在内核模式访问。
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	//创建线程
	NTSTATUS Status = CreateThreadEx(
		&ThreadHandle, THREAD_QUERY_LIMITED_INFORMATION, &ObjectAttributes,
		ZwCurrentProcess(), ThreadProcedure, ParameterData, Flags,
		0, 0x1000, 0x100000, NULL
	);
	// 等待线程完成
	if (NT_SUCCESS(Status) && IsWait != FALSE)
	{
		//60s
		LARGE_INTEGER Timeout = { 0 };
		Timeout.QuadPart = -(60ll * 10 * 1000 * 1000);

		Status = ZwWaitForSingleObject(ThreadHandle, TRUE, &Timeout);
		if (NT_SUCCESS(Status))
		{
			//查询线程退出码
			THREAD_BASIC_INFORMATION ThreadBasicInfo = { 0 };
			ULONG ReturnLength = 0;

			Status = ZwQueryInformationThread(ThreadHandle, ThreadBasicInformation, &ThreadBasicInfo, sizeof(ThreadBasicInfo), &ReturnLength);
			if (NT_SUCCESS(Status) && ExitStatus)
			{
				*ExitStatus = ThreadBasicInfo.ExitStatus;
			}
			else if (!NT_SUCCESS(Status))
			{

			}
		}
		else
		{
		}
	}
	else
	{

	}
	if (ThreadHandle)
	{
		ZwClose(ThreadHandle);
	}
	return Status;
}
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
	IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
)
{
	NTSTATUS Status = STATUS_SUCCESS;
	LPFN_NTCREATETHREADEX NtCreateThreadEx = NULL;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE  SystemServiceDescriptorTable = GetKeServiceDescriptorTable();     //ssdt表中获取
	ULONG_PTR ServiceIndex = 0;

	//Ssdt 中的函数
	if (SystemServiceDescriptorTable)
	{
		//检查索引范围
		if (!GetNtXXXServcieIndex("NtCreateThreadEx", &ServiceIndex))
		{
			return STATUS_UNSUCCESSFUL;
		}

		GetNtXXXServcieAddress(ServiceIndex, &NtCreateThreadEx);
	}

	if (NtCreateThreadEx)
	{


#ifdef  _WIN64

		PUCHAR v1 = (PUCHAR)PsGetCurrentThread() + 0x1F6;

#else 
		PUCHAR v1 = (PUCHAR)PsGetCurrentThread() + 0x13a;
#endif //  _WIN64


		UCHAR PreviousMode = *v1;
		*v1 = KERNEL_MODE;

		//创建线程
		Status = NtCreateThreadEx(
			ThreadHandle, DesiredAccess, ObjectAttributes,
			ProcessHandle, StartAddress, ParameterData,   //ParameterData要被压入参数列表
			Flags, StackZeroBits, ViewSizeOfStackCommit,
			ViewSizeOfStackReserve, AttributeList
		);

		//
		//恢复之前的线程模式
		*v1 = PreviousMode;
	}
	else
		Status = STATUS_NOT_FOUND;

	return Status;
}