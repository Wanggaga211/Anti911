#include "ProcessHelper.h"
#include "SystemHelper.h"
#include "ObjectHelper.h"
#include "IoControlRoutine.h"
#include "MemoryHelper.h"
#include "ProcssPath.h"

PROTECT_PROCESS_INFORMATION __ProtectProcessInfo = { 0 };

void InitializeProcessSource()
{
    ExInitializeFastMutex(&__ProtectProcessInfo.FastMutex);
}
NTSTATUS PsEnumProcess(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PPROCESSES_INFORMATION ProcessesInfo = (PPROCESSES_INFORMATION)OutputBuffer;

    // 参数检查
    if (!InputBuffer ||
        InputBufferLength != sizeof(OPERATE_TYPE) ||
        !OutputBuffer ||
        OutputBufferLength < sizeof(PROCESSES_INFORMATION))
    {
        return STATUS_INVALID_PARAMETER;
    }

    return PsEnumProcessInternal(ProcessesInfo, OutputBufferLength);
}
NTSTATUS PsEnumProcessInternal(PPROCESSES_INFORMATION ProcessesInfo, ULONG OutputBufferLength)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG NumberOfProcess = (OutputBufferLength - sizeof(PPROCESSES_INFORMATION)) / sizeof(PROCESS_INFORMATIONEX);

    if (!ProcessesInfo)
    {
        return STATUS_INVALID_PARAMETER;
    }
  
    //EnumProcessByService(ProcessesInfo, NumberOfProcess);

    EnumProcessByActiveLink(ProcessesInfo, NumberOfProcess);

    if (NumberOfProcess >= ProcessesInfo->NumberOfProcess)
    {
        Status = STATUS_SUCCESS;
    }
    else
    {
        Status = STATUS_BUFFER_TOO_SMALL;
    }

    return Status;
}
NTSTATUS PsProtectProcess(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCOMMUNICATE_PROTECT_PROCESS v1 = (PCOMMUNICATE_PROTECT_PROCESS)InputBuffer;

    // 参数检查
    if (!InputBuffer ||
        InputBufferLength != sizeof(COMMUNICATE_PROTECT_PROCESS))
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (int i = 0; i < InputBufferLength / sizeof(HANDLE); i++)
    {
       
       
        auto ProcessIdentify = v1->ProcessIdentitys[i];
        if (ProcessIdentify == 0) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (IsProcessIdentifyExist(ProcessIdentify))
            continue;

        if (__ProtectProcessInfo.NumberOfProcess == MAX_PATH)
        {
            Status = STATUS_TOO_MANY_CONTEXT_IDS;
            break;
        }

        if (!InsertProcessIdentify(ProcessIdentify))
        {
            Status = STATUS_UNSUCCESSFUL;
            break;
        }
    }

    return Status;

}
NTSTATUS PsUnprotectProcess(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCOMMUNICATE_PROTECT_PROCESS v1 = (PCOMMUNICATE_PROTECT_PROCESS)InputBuffer;

    // 参数检查
    if (!InputBuffer ||
        InputBufferLength != sizeof(COMMUNICATE_PROTECT_PROCESS))
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (int i = 0; i < InputBufferLength / sizeof(HANDLE); i++)
    {
        auto ProcessIdentify = v1->ProcessIdentitys[i];
        if (ProcessIdentify == 0)
        {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (!RemoveProcessIdentify(ProcessIdentify))
            continue;

        if (__ProtectProcessInfo.NumberOfProcess == 0)
            break;
    }
 
    return Status;

}
NTSTATUS PsClearProtectProcess(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{
    NTSTATUS Status = STATUS_SUCCESS;

    // 参数检查
    if (!InputBuffer ||
        InputBufferLength != sizeof(OPERATE_TYPE))
    {
        return STATUS_INVALID_PARAMETER;
    }
    ClearProcessIdentify();
}
NTSTATUS PsHideProcess(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PEPROCESS EProcess1 = NULL;
    PEPROCESS EProcess2 = NULL;
    PEPROCESS v1 = NULL;
    char* ImageFileName1 = NULL;
    char* ImageFileName2 = NULL;
    PLIST_ENTRY ListEntry;
    PCOMMUNICATE_HIDE_PROCESS v5 = (PCOMMUNICATE_HIDE_PROCESS)InputBuffer;
    // 参数检查
    if (!InputBuffer ||
        InputBufferLength != sizeof(COMMUNICATE_HIDE_PROCESS))
    {
        return STATUS_INVALID_PARAMETER;
    }
    auto ProcessIdentify = v5->ProcessIdentity;
    if (ProcessIdentify == 0)
    {
        Status = STATUS_INVALID_PARAMETER;
       
    }
    else
    {

#ifdef _WIN64
        int Offset1 = 0x2e0;
        int Offset2 = 0x188;
#else
        int Offset1 = 0x16c;
        int Offset2 = 0x0b8;
#endif 

        //通过进程Id获得进程对象
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(v5->ProcessIdentity), &EProcess1)))
        {
            if (EProcess1 != NULL)
            {
              
                ImageFileName1 = (char*)((UINT8*)EProcess1 + Offset1);   //将要隐藏的进程名称

                v1 = __System;
                ListEntry = (PLIST_ENTRY)((UINT8*)__System + Offset2);  //0x188
                EProcess2 = (PEPROCESS)(((ULONG_PTR)(ListEntry->Blink)) - Offset2);  //System的前一个对象

                ListEntry = NULL;
                while (v1 != EProcess2)  //System!=空头节点
                {
                    ImageFileName2 = (char*)((UINT8*)v1 + Offset1);   //System.exe   Calc.exe
                   //DbgPrint("ImageFileName:%s\r\n",szImageFileName);   
                    ListEntry = (PLIST_ENTRY)((ULONG_PTR)v1 + Offset2);
                    if (strstr(ImageFileName2, ImageFileName1) != NULL)
                    {
                        if (ListEntry != NULL)
                        {
                            RemoveEntryList(ListEntry);
                            break;
                        }
                    }
                    v1 = (PEPROCESS)(((ULONG_PTR)(ListEntry->Flink)) - Offset2);
                }
            }
            ObfDereferenceObject(EProcess1);
        }
   
    }
    return Status;
}
BOOLEAN IsProcessIdentifyExist(HANDLE ProcessIdentify)
{
    BOOLEAN IsOk = FALSE;
    ExAcquireFastMutex(&__ProtectProcessInfo.FastMutex);
    for (int i = 0; i < __ProtectProcessInfo.NumberOfProcess; i++)
    {
        if (__ProtectProcessInfo.ProcessIdentitys[i] == ProcessIdentify)
        {
            IsOk = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&__ProtectProcessInfo.FastMutex);
    return IsOk;
}
BOOLEAN InsertProcessIdentify(HANDLE ProcessIdentify)
{
    BOOLEAN IsOk = FALSE;
    ExAcquireFastMutex(&__ProtectProcessInfo.FastMutex);
    for (int i = 0; i < MAX_PATH; i++)
    {

        if (__ProtectProcessInfo.ProcessIdentitys[i] == 0)
        {
            // empty slot
            __ProtectProcessInfo.ProcessIdentitys[i] = ProcessIdentify;
            __ProtectProcessInfo.NumberOfProcess++;
            IsOk = TRUE;

            break;
        }
    }
    ExReleaseFastMutex(&__ProtectProcessInfo.FastMutex);
    return IsOk;
}
BOOLEAN RemoveProcessIdentify(HANDLE ProcessIdentify)
{
    BOOLEAN IsOk = FALSE;
    ExAcquireFastMutex(&__ProtectProcessInfo.FastMutex);
    for (int i = 0; i < MAX_PATH; i++)
    {
        if (__ProtectProcessInfo.ProcessIdentitys[i] == ProcessIdentify) 
        {
            __ProtectProcessInfo.ProcessIdentitys[i] = 0;
            __ProtectProcessInfo.NumberOfProcess--;
            IsOk =  TRUE;
        }
    }
     
    ExReleaseFastMutex(&__ProtectProcessInfo.FastMutex);
    return IsOk;
}

VOID ClearProcessIdentify()
{

    ExAcquireFastMutex(&__ProtectProcessInfo.FastMutex);
    memset(&__ProtectProcessInfo.ProcessIdentitys, 0, sizeof(__ProtectProcessInfo.ProcessIdentitys));
    __ProtectProcessInfo.NumberOfProcess = 0;

    ExReleaseFastMutex(&__ProtectProcessInfo.FastMutex);

}
VOID EnumProcessByService(PPROCESSES_INFORMATION ProcessesInfo, ULONG NumberOfProcess)
{

    ULONG ReturnValue = 0, i = 0;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVOID v5 = NULL;
    ULONG v7 = 0x10000;
    PSYSTEM_PROCESS_INFORMATION v1 = NULL;
  
    do
    {
        v5 = AllocatePoolWithTag(PagedPool,v7);
        if (v5)
        {
            Status = ZwQuerySystemInformation(SystemProcessInformation, v5, v7, &ReturnValue);
            if (NT_SUCCESS(Status))
            {
                v1 = (PSYSTEM_PROCESS_INFORMATION)v5;

                while (1)
                {
                    PEPROCESS EProcess = NULL;

                    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(v1->UniqueProcessId), &EProcess)))
                    {
                     
                    
                        SetProcessInfoToList(ProcessesInfo, NumberOfProcess,EProcess);
                        ObfDereferenceObject(EProcess);
                    }

                    if (v1->NextEntryOffset == 0)
                    {
                        break;
                    }

                    v1 = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)v1 + v1->NextEntryOffset);
                }
            }
            else
            {
                v7 *= 2;
            }

            FreePoolWithTag(v5);
            v5 = NULL;
        }
        else
        {
            break;
        }

    } while (Status == STATUS_INFO_LENGTH_MISMATCH && ++i < 10);
}
VOID EnumProcessByActiveLink(PPROCESSES_INFORMATION ProcessesInfo, ULONG NumberOfProcess)
{

    PEPROCESS  EProcess = NULL;
    PEPROCESS  v1 = NULL;
    PEPROCESS  v2 = NULL;
    BOOLEAN    IsOk = FALSE;
    PLIST_ENTRY  ListEntry = NULL;
    char* ImageFileName = NULL;
    //通过进程EProcess (ObjectHeader ObjectBody)
    /*
    kd> !process 0 0
    PROCESS 89c12a60  SessionId: 1  Cid: 0954    Peb: 7ffda000  ParentCid: 08f4
    DirBase: beaf74a0  ObjectTable: 84153c90  HandleCount: 759.
    Image: explorer.exe


    kd> dt _eprocess 89c12a60
    nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x098 ProcessLock      : _EX_PUSH_LOCK
   +0x0a0 CreateTime       : _LARGE_INTEGER 0x1d30e84`2ac09b37
   +0x0a8 ExitTime         : _LARGE_INTEGER 0x0
   +0x0b0 RundownProtect   : _EX_RUNDOWN_REF
   +0x0b4 UniqueProcessId  : 0x00000954 Void
   +0x0b8 ActiveProcessLinks : _LIST_ENTRY [ 0x89ed14c0 - 0x89941c40 ]
   +0x160 Filler           : 0
   +0x168 Session          : 0x923c3000 Void
   +0x16c ImageFileName    : [15]  "explorer.exe"

   kd> dt _List_entry
   nt!_LIST_ENTRY
   +0x000 Flink            : Ptr32 _LIST_ENTRY
   +0x004 Blink            : Ptr32 _LIST_ENTRY


   kd> dt _EProcess 0x89ed14c0-0x0b8
   nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x098 ProcessLock      : _EX_PUSH_LOCK
   +0x0a0 CreateTime       : _LARGE_INTEGER 0x1d30e84`2af75ade
   +0x0a8 ExitTime         : _LARGE_INTEGER 0x0
   +0x0b0 RundownProtect   : _EX_RUNDOWN_REF
   +0x0b4 UniqueProcessId  : 0x000009f0 Void
   +0x0b8 ActiveProcessLinks : _LIST_ENTRY [ 0x89f3edf8 - 0x89c12b18 ]
   +0x160 PageDirectoryPte : _HARDWARE_PTE
   +0x160 Filler           : 0
   +0x168 Session          : 0x9236a000 Void
   +0x16c ImageFileName    : [15]  "msdtc.exe"
   +0x17b PriorityClass    : 0x2 ''


   [空头][System][][][][explorer.exe][msdtc.exe]   [calc.exe]
   #define ACTIVEPROCESSLINKS_EPROCESS  0x0b8

    */

#ifdef  _WIN64
    ULONG_PTR ActiveProcessLinks = 0x188;
#else 

    ULONG_PTR ActiveProcessLinks = 0x0b8;
#endif //

    //获得当前进程的EProcess(System.exe)
    EProcess = PsGetCurrentProcess();
    if (EProcess == NULL)
    {
        return;
    }

    v1 = EProcess;   //System.exe  EProcess

    ListEntry = (PLIST_ENTRY)((UINT8*)EProcess + ActiveProcessLinks);  //0x188

    //获得System.exe(EProcess)的前一个EProcess(实际上是一个空头节点)
    v2 = (PEPROCESS)(((UINT8*)(ListEntry->Blink)) - ActiveProcessLinks);



    ListEntry = NULL;
    while (v1 != v2)  //System!=空头节点
    { 
        SetProcessInfoToList(ProcessesInfo, NumberOfProcess, v1);
        ListEntry = (PLIST_ENTRY)((UINT8*)v1 + ActiveProcessLinks);
        v1 = (PEPROCESS)(((UINT8*)(ListEntry->Flink)) - ActiveProcessLinks);
    }
}



VOID SetProcessInfoToList(PPROCESSES_INFORMATION ProcessesInfo, ULONG NumberOfProcess, PEPROCESS EProcess)
{
   
    ULONG v1 = 0;
  

    v1 = ProcessesInfo->NumberOfProcess;

    if (NumberOfProcess > v1)
    {
     
#ifdef  _WIN64
        ULONG_PTR ProcessIdentity = *(PULONG_PTR)((ULONG_PTR)EProcess + 0x180);
#else 
       
        ULONG_PTR ProcessIdentity = *(PULONG_PTR)((ULONG_PTR)EProcess + 0x0b4);
#endif //  _WIN64
        if (ProcessIdentity &&
            MmIsAddressValid((PVOID)ProcessIdentity))
        {
            ProcessesInfo->ProcessInfo[v1].ProcessIdentity = ProcessIdentity;
        }
        else
        {
       
            ProcessesInfo->ProcessInfo[v1].ProcessIdentity = PsGetProcessId(EProcess);   //和偏移的方法一致
        }

        ProcessesInfo->ProcessInfo[v1].CreateTime = PsGetProcessCreateTimeQuadPart(EProcess);
        ProcessesInfo->ProcessInfo[v1].ParentPid = (ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId(EProcess);
        ProcessesInfo->ProcessInfo[v1].EProcess =  EProcess;

        wchar_t ProcessPath[MAX_PATH] = { 0 };
        GetProcessPathByPeb(EProcess, ProcessPath,MAX_PATH);
        memcpy(ProcessesInfo->ProcessInfo[v1].ProcessPath, ProcessPath, MAX_PATH);
    }

    ProcessesInfo->NumberOfProcess++;
}
















//获取用户模块
PVOID GetUserModuleHandle(IN PEPROCESS EProcess, IN PUNICODE_STRING ModuleName)
{
	if (EProcess == NULL)
		return NULL;

	__try
	{
		LARGE_INTEGER TimeOut = { 0 };
		TimeOut.QuadPart = -250ll * 10 * 1000;			//250 ms.

		PPEB Peb = PsGetProcessPeb(EProcess);  //通过进程对象获取进程Peb
		if (!Peb)
		{

			return NULL;
		}
		for (INT i = 0; !Peb->Ldr && i < 10; i++)
		{
			KeDelayExecutionThread(KernelMode, TRUE, &TimeOut);
		}
		if (!Peb->Ldr)
		{
			return NULL;
		}

		//遍历链表
		for (PLIST_ENTRY ListEntry = Peb->Ldr->InLoadOrderModuleList.Flink;
			ListEntry != &Peb->Ldr->InLoadOrderModuleList;
			ListEntry = ListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (RtlCompareUnicodeString(&LdrDataTableEntry->BaseDllName, ModuleName, TRUE) == 0)
				return LdrDataTableEntry->DllBase;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return NULL;
}
NTSTATUS PsLookupThreadByEProcess(PEPROCESS EProcess, PETHREAD* EThread)
{
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE ProcessIdentity = PsGetProcessId(EProcess);   //目标进程
    //0x00000000`0000059c
    PVOID BufferData = ExAllocatePool(NonPagedPool, 1024 * 1024);


    //系统下的所有进程信息
    PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)BufferData;


    //返回值
    if (EThread == NULL)
        return STATUS_INVALID_PARAMETER;

    //动态内存是否成功
    if (!SystemProcessInfo)
    {
        return STATUS_NO_MEMORY;
    }

    //获得进程队列
    Status = ZwQuerySystemInformation(SystemProcessInformation, SystemProcessInfo, 1024 * 1024, NULL);
    if (!NT_SUCCESS(Status))
    {
        ExFreePool(BufferData);
        return Status;
    }
    //查找目标进程
    if (NT_SUCCESS(Status))
    {
        Status = STATUS_NOT_FOUND;
        for (;;)
        {
            if (SystemProcessInfo->UniqueProcessId == ProcessIdentity)   //枚举出来的进程与目标进程一致
            {
                Status = STATUS_SUCCESS;
                break;
            }
            else if (SystemProcessInfo->NextEntryOffset)
                SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)SystemProcessInfo + SystemProcessInfo->NextEntryOffset);
            else
                break;
        }
    }

    //查找目标线程
    if (NT_SUCCESS(Status))
    {
        Status = STATUS_NOT_FOUND;

        //获得第一个线程
        for (ULONG i = 0; i < SystemProcessInfo->NumberOfThreads; i++)
        {
            if (SystemProcessInfo->TH[i].ClientId.UniqueThread == PsGetCurrentThreadId())
            {
                continue;  //除过我们自己
            }


            //获取第一个不是自己的线程
            Status = PsLookupThreadByThreadId(SystemProcessInfo->TH[i].ClientId.UniqueThread, EThread);
            break;
        }
    }
    else
    {
    }
    if (BufferData)
    {
        ExFreePool(BufferData);
    }

    //没有合适的线程
    if (!*EThread)
    {
        Status = STATUS_NOT_FOUND;
    }
    return Status;
}
BOOLEAN PsIsProcessTermination(PEPROCESS EProcess)
{
	LARGE_INTEGER v1 = { 0 };
	return KeWaitForSingleObject(EProcess, Executive, KernelMode, FALSE, &v1) == STATUS_WAIT_0;
}

#ifdef _WIN64

BOOLEAN CheckNtdll32(ULONG VirtualAddress, PULONG DllBase)
{
    PPEB_LDR_DATA32			PebLdrData32;
    PLDR_DATA_TABLE_ENTRY32 LdrDataTableEntry32;

    PebLdrData32 = (PPEB_LDR_DATA32)((PPEB32)PsGetCurrentProcessWow64Process())->Ldr;

    if (!PebLdrData32)		// This can happen while the WoW64 subsystem is still initializing
        return FALSE;

    LdrDataTableEntry32 = (PLDR_DATA_TABLE_ENTRY32)PebLdrData32->InLoadOrderModuleList.Flink;	// Main exe
    LdrDataTableEntry32 = (PLDR_DATA_TABLE_ENTRY32)LdrDataTableEntry32->InLoadOrderLinks.Flink;		// Ntdll

    if (((ULONG_PTR)VirtualAddress >= (ULONG_PTR)LdrDataTableEntry32->DllBase) &&
        ((ULONG_PTR)VirtualAddress < ((ULONG_PTR)LdrDataTableEntry32->DllBase + LdrDataTableEntry32->SizeOfImage)))
    {

        *DllBase = LdrDataTableEntry32->DllBase;
        return TRUE;
    }
    return FALSE;
}
#endif // _WIN64

BOOLEAN CheckNtdll64(ULONG_PTR VirtualAddress, PULONG_PTR DllBase)
{
    PPEB_LDR_DATA			PebLdrData;
    PLDR_DATA_TABLE_ENTRY   LdrDataTableEntry;

    PebLdrData = ((PPEB_LDR_DATA)PsGetProcessPeb(PsGetCurrentProcess())->Ldr);

    LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)PebLdrData->InLoadOrderModuleList.Flink;	// Main exe
    LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)LdrDataTableEntry->InLoadOrderLinks.Flink;		// Ntdll

    if (((ULONG_PTR)VirtualAddress >= (ULONG_PTR)LdrDataTableEntry->DllBase) &&
        ((ULONG_PTR)VirtualAddress < ((ULONG_PTR)LdrDataTableEntry->DllBase + LdrDataTableEntry->SizeOfImage)))
    {
      

        *DllBase = (ULONG_PTR)LdrDataTableEntry->DllBase;
        return TRUE;
    }
    return FALSE;
}



BOOLEAN PsIsRealProcess(PEPROCESS EProcess)
{
    //查看EProcess是否具有进程对象特征
    ULONG_PTR    ObjectType;
    ULONG_PTR    ObjectTypeAddress;
    ULONG_PTR    ProcessType = ((ULONG_PTR)*PsProcessType);   //系统第一模块导出的全局变量
    /*
     dd PsProcessType
     849aa104  878dcd28
    */

    //从系统中的第一个模块(ntkrnlpa.exe)中的导出表中获得函数地址

    if (__ObGetObjectType == NULL)
    {
        UNICODE_STRING v1;
        RtlInitUnicodeString(&v1, L"ObGetObjectType");
        __ObGetObjectType = (LPFN_OBGETOBJECTTYPE)MmGetSystemRoutineAddress(&v1);
    }
    /*
    0: kd> dd __ObGetObjectType
    a8189008  84a99b68 00000000 00000000 00000000
    0: kd> u  84a99b68
    nt!ObGetObjectType:
    84a99b68 8bff            mov     edi,edi
    84a99b6a 55              push    ebp
    84a99b6b 8bec            mov     ebp,esp
    84a99b6d 8b4508          mov     eax,dword p
    */
    if (ProcessType && EProcess && MmIsAddressValid((PVOID)(EProcess)))
    {

        ObjectType = __ObGetObjectType((PVOID)EProcess);
        if (ObjectType &&
            ProcessType == ObjectType)
        {
            //当前EProcess是一个有效的进程
            return TRUE;
        }


    }
    return FALSE;
}







//进程路径
