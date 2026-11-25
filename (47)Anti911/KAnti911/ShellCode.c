#include "ShellCode.h"


//线程注入
PINJECT_BUFFER GetWow64LoadCode1(IN PVOID LdrLoadDll, IN PUNICODE_STRING DllPath, IN SIZE_T ViewSize)  //一个动态库的完成路径
{
	NTSTATUS Status = STATUS_SUCCESS;
	PINJECT_BUFFER v5 = NULL;
	//
	//NtStatus = LdrLoadDll(FullPath      &ModuleHandle)
	// Code
	UCHAR ShellCode[] =
	{
		0x68, 0, 0, 0, 0,                       // push ModuleHandle            offset +1 
		0x68, 0, 0, 0, 0,                       // push FullPath(UnicodeString)          offset +6
		0x6A, 0,                                // push Flags  
		0x6A, 0,                                // push FullPath(wchar*)
		0xE8, 0, 0, 0, 0,                       // call LdrLoadDll              offset +15
		0xBA, 0, 0, 0, 0,                       // mov edx, COMPLETE_OFFSET     offset +20   
		0x8B,0x4D,0x08,							// mov  ecx,dword ptr[ebp + 8]  CALL_COMPLETE
		0x89,0x0A,							    // mov dword ptr [edx],ecx
		0xBA, 0, 0, 0, 0,                       // mov edx, STATUS_OFFSET       offset +30
		0x89, 0x02,                             // mov [edx], eax
		0xC2, 0x04, 0x00                        // ret 4
	};


	//启动一个线程执行v5中的shellcode 
	//ebp+8   ParameterData(CALL_COMPLETE)

	/*
	NTSTATUS
NTAPI
PspCreateThread(OUT PHANDLE ThreadHandle,
				IN ACCESS_MASK DesiredAccess,
				IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
				IN HANDLE ProcessHandle,
				IN PEPROCESS TargetProcess,
				OUT PCLIENT_ID ClientId,
				IN PCONTEXT ThreadContext,
				IN PINITIAL_TEB InitialTeb,
				IN BOOLEAN CreateSuspended,
				IN PKSTART_ROUTINE StartRoutine OPTIONAL,
				IN PVOID StartContext OPTIONAL)

	typedef
VOID
(*PKSTART_ROUTINE) (
	IN PVOID StartContext
	);       //由于该回调函数的调用约定是cdecl所以自己回复参数列表
	*/

	//目标进程空间中申请内存
	Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &v5, 0, &ViewSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(Status))
	{

		PUNICODE_STRING v1 = &(v5->DllPath);
		v1->Length = DllPath->Length;
		v1->MaximumLength = DllPath->MaximumLength;
		v1->Buffer = v5->BufferData;   //被注入动态库的完整路径

		// Copy path
		memcpy((PVOID)v1->Buffer, DllPath->Buffer, DllPath->Length);

		// Copy code
		memcpy(v5, ShellCode, sizeof(ShellCode));

		// Fill stubs
		*(ULONG*)((PUCHAR)v5 + 1) = (ULONG)(ULONG_PTR) & (v5->ModuleHandle);    //LdrLoadDll函数的第四个参加
		*(ULONG*)((PUCHAR)v5 + 6) = (ULONG)(ULONG_PTR)v1;
		*(ULONG*)((PUCHAR)v5 + 15) = (ULONG)((ULONG_PTR)LdrLoadDll - ((ULONG_PTR)v5 + 15) - 5 + 1);   //计算呼叫函数LdrLoadDll的偏移
		*(ULONG*)((PUCHAR)v5 + 20) = (ULONG)(ULONG_PTR)&v5->Complete;
		*(ULONG*)((PUCHAR)v5 + 30) = (ULONG)(ULONG_PTR)&v5->Status;

		return v5;
	}
	return NULL;
}
PINJECT_BUFFER GetWow64UnloadCode1(IN PVOID ModuleHandle, IN PVOID LdrUnloadDll, IN SIZE_T ViewSize)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PINJECT_BUFFER v5 = NULL;
	//NtStatus = LdrLoadDll(FullPath      &ModuleHandle)


	// Code
	UCHAR ShellCode[] =
	{
		0x68, 0, 0, 0, 0,                       // push ModuleHandle            offset +1 
		0xE8, 0, 0, 0, 0,                       // call LdrUnLoadDll              offset +15
		0xBA, 0, 0, 0, 0,                       // mov edx, COMPLETE_OFFSET     offset +20  
		0x8B, 0x4D,0x08,							// mov  ecx,dword ptr[ebp + 8]
		0x89,0x0A,							    // mov dword ptr [edx],ecx
		0xBA, 0, 0, 0, 0,                       // mov edx, STATUS_OFFSET       offset +30
		0x89, 0x02,                             // mov [edx], eax
		0xC2, 0x04, 0x00                        // ret 4									
	};

	Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &v5, 0, &ViewSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(Status))
	{

		memcpy(v5, ShellCode, sizeof(ShellCode));

		// Fill stubs
		*(ULONG*)((PUCHAR)v5 + 1) = (ULONG)(ULONG_PTR)(ModuleHandle);    //LdrLoadDll函数的第四个参加

		*(ULONG*)((PUCHAR)v5 + 6) = (ULONG)((ULONG_PTR)LdrUnloadDll - ((ULONG_PTR)v5 + 6) - 5 + 1);   //计算呼叫函数LdrLoadDll的偏移
		*(ULONG*)((PUCHAR)v5 + 11) = (ULONG)(ULONG_PTR) & ((PINJECT_BUFFER)v5)->Complete;
		*(ULONG*)((PUCHAR)v5 + 21) = (ULONG)(ULONG_PTR) & ((PINJECT_BUFFER)v5)->Status;
		return v5;
	}
	return NULL;
}
PINJECT_BUFFER GetNativeLoadCode1(IN PVOID LdrLoadDll, IN PUNICODE_STRING DllPath, IN SIZE_T ViewSize)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PINJECT_BUFFER v5 = NULL;


	UCHAR ShellCode[] =
	{
		0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28   
		0x48, 0x8B, 0xD9,						// mov rbx,rcx      //参数
		0x48, 0x31, 0xC9,                       // xor rcx, rcx
		0x48, 0x31, 0xD2,                       // xor rdx, rdx
		0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +15
		0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +25
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +35
		0xFF, 0xD0,                             // call rax   //e8 offset    ff 15 [][][][]  
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +47
		0x48, 0x8B, 0xCB,						// mov rcx,rbx       //参数
		0x48, 0x89, 0x0A,						// mov qword ptr[rdx], rcx  //参数放入v5结构中
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, STATUS_OFFSET   offset +63
		0x89, 0x02,                             // mov [rdx], eax
		0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
		0xC3                                    // ret     //fastcall调用约定
	};

	Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &v5, 0, &ViewSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(Status))
	{

		PUNICODE_STRING v1 = &v5->DllPath;
		v1->Length = DllPath->Length;
		v1->MaximumLength = DllPath->MaximumLength;;
		v1->Buffer = v5->BufferData;

		memcpy((PVOID)v1->Buffer, DllPath->Buffer, DllPath->Length);
		// Copy code
		memcpy(v5, ShellCode, sizeof(ShellCode));

		// Fill stubs
		*(ULONGLONG*)((PUCHAR)v5 + 15) = (ULONGLONG)v1;
		*(ULONGLONG*)((PUCHAR)v5 + 25) = (ULONGLONG)&v5->ModuleHandle;
		*(ULONGLONG*)((PUCHAR)v5 + 35) = (ULONGLONG)LdrLoadDll;
		*(ULONGLONG*)((PUCHAR)v5 + 47) = (ULONGLONG)&v5->Complete;
		*(ULONGLONG*)((PUCHAR)v5 + 63) = (ULONGLONG)&v5->Status;

		return v5;
	}

	return NULL;
}
PINJECT_BUFFER GetNativeUnloadCode1(PVOID ModuleHandle, IN PVOID LdrUnloadDll, IN SIZE_T ViewSize)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PINJECT_BUFFER v5 = NULL;
	UCHAR ShellCode[] =
	{
		0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28   
		0x48, 0x8B, 0xD9,						// mov rbx,rcx      //参数

		0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rcx, ModuleHandle     
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrUnloadDll      
		0xFF, 0xD0,                             // call rax  


		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +31
		0x48, 0x8B, 0xCB,						// mov rcx,rbx       //参数
		0x48, 0x89, 0x0A,						// mov qword ptr[rdx], rcx  //参数放入v5结构中
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, STATUS_OFFSET   
		0x89, 0x02,                             // mov [rdx], eax
		0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
		0xC3                                    // ret     //fastcall调用约定
	};
	Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &v5, 0, &ViewSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(Status))
	{
		// Copy code
		memcpy(v5, ShellCode, sizeof(ShellCode));

		// Fill stubs
		*(ULONGLONG*)((PUCHAR)v5 + 9) = (ULONGLONG)(ModuleHandle);

		*(ULONGLONG*)((PUCHAR)v5 + 19) = (ULONGLONG)LdrUnloadDll;

		*(ULONGLONG*)((PUCHAR)v5 + 31) = (ULONGLONG) & ((PINJECT_BUFFER)v5)->Complete;
		*(ULONGLONG*)((PUCHAR)v5 + 47) = (ULONGLONG) & ((PINJECT_BUFFER)v5)->Status;

		return v5;
	}

	return NULL;
}


//Apc注入
PINJECT_BUFFER GetWow64LoadCode2(IN PVOID LdrLoadDll, IN PUNICODE_STRING DllPath, IN SIZE_T ViewSize)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PINJECT_BUFFER v5 = NULL;
	// Code
	UCHAR ShellCode[] =
	{
		0x60,          //pusha  
		0x9c,          //pushf
		0x68, 0, 0, 0, 0,                       // push ModuleHandle            offset +1 
		0x68, 0, 0, 0, 0,                       // push ModuleFileName          offset +6
		0x6A, 0,                                // push Flags  
		0x6A, 0,                                // push PathToFile
		0xE8, 0, 0, 0, 0,                       // call LdrLoadDll              offset +15
		0xBA, 0, 0, 0, 0,                       // mov edx, COMPLETE_OFFSET     offset +20
		0xB9, 0x7E, 0x1E, 0x37,0xC0,            // mov ecx, CALL_COMPLETE
		0x89, 0x0A,							    // mov dword ptr [edx],ecx
		0xBA, 0, 0, 0, 0,                       // mov edx, STATUS_OFFSET       offset +30
		0x89, 0x02,                             // mov [edx], eax
		0x9d,       //popf
		0x61,       //popa
		0xC3                                    // ret 4
	};
	Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &v5, 0, &ViewSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(Status))
	{
		PUNICODE_STRING32 v1 = &v5->DllPath;
		v1->Length = DllPath->Length;
		v1->MaximumLength = DllPath->MaximumLength;
		v1->Buffer = (ULONG)(ULONG_PTR)v5->BufferData;

		memcpy((PVOID)v1->Buffer, DllPath->Buffer, DllPath->Length);

		memcpy(v5, ShellCode, sizeof(ShellCode));

		*(ULONG*)((PUCHAR)v5 + 3) = (ULONG)(ULONG_PTR)&v5->ModuleHandle;
		*(ULONG*)((PUCHAR)v5 + 8) = (ULONG)(ULONG_PTR)v1;
		*(ULONG*)((PUCHAR)v5 + 17) = (ULONG)((ULONG_PTR)LdrLoadDll - ((ULONG_PTR)v5 + 17) - 5 + 1);
		*(ULONG*)((PUCHAR)v5 + 22) = (ULONG)(ULONG_PTR)&v5->Complete;
		*(ULONG*)((PUCHAR)v5 + 34) = (ULONG)(ULONG_PTR)&v5->Status;

		return v5;
	}
	return NULL;
}
PINJECT_BUFFER GetWow64UnloadCode2(IN PVOID ModuleHandle, IN PVOID LdrUnloadDll, IN SIZE_T ViewSize)
{
	// Code
	NTSTATUS Status = STATUS_SUCCESS;
	PINJECT_BUFFER v5 = NULL;
	UCHAR ShellCode[] =
	{
		0x60,
		0x9c,
		0x68, 0, 0, 0, 0,                       // push ModuleHandle            offset +1 
		0xE8, 0, 0, 0, 0,                       // call LdrUnLoadDll              offset +15
		0xBA, 0, 0, 0, 0,                       // mov edx, COMPLETE_OFFSET     offset +20
		0xB9, 0x7E, 0x1E, 0x37,0xC0,            // mov ecx, CALL_COMPLETE
		0x89, 0x0A,							    // mov dword ptr [edx],ecx
		0xBA, 0, 0, 0, 0,                       // mov edx, STATUS_OFFSET       offset +30
		0x89, 0x02,                             // mov [edx], eax	
		0x9d,
		0x61,
		0xC3,                                    // ret 
	};


	Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &v5, 0, &ViewSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(Status))
	{
		memcpy(v5, ShellCode, sizeof(ShellCode));

		// Fill stubs
		*(ULONG*)((PUCHAR)v5 + 3) = (ULONG)(ULONG_PTR)(ModuleHandle);    //LdrLoadDll函数的第四个参加
		*(ULONG*)((PUCHAR)v5 + 8) = (ULONG)((ULONG_PTR)LdrUnloadDll - ((ULONG_PTR)v5 + 8) - 5 + 1);   //计算呼叫函数LdrLoadDll的偏移
		*(ULONG*)((PUCHAR)v5 + 13) = (ULONG)(ULONG_PTR) & ((PINJECT_BUFFER)v5)->Complete;
		*(ULONG*)((PUCHAR)v5 + 25) = (ULONG)(ULONG_PTR) & ((PINJECT_BUFFER)v5)->Status;

		return v5;
	}

	return NULL;

}
PINJECT_BUFFER GetNativeLoadCode2(IN PVOID LdrLoadDll, IN PUNICODE_STRING DllPath, IN SIZE_T ViewSize)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PINJECT_BUFFER v5 = NULL;
	// Code
	UCHAR ShellCode[] =
	{
		0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28
		0x48, 0x31, 0xC9,                       // xor rcx, rcx
		0x48, 0x31, 0xD2,                       // xor rdx, rdx
		0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +12
		0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +28
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +32
		0xFF, 0xD0,                             // call rax      // 最安全最稳定
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +44
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [rdx], CALL_COMPLETE                  //APC使用
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, STATUS_OFFSET   offset +63
		0x89, 0x02,                             // mov [rdx], eax
		0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
		0xC3                                    // ret
	};

	Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &v5, 0, &ViewSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(Status))
	{

		// Copy path
		PUNICODE_STRING v1 = &v5->DllPath;
		v1->Length = DllPath->Length;
		v1->MaximumLength = DllPath->MaximumLength;
		v1->Buffer = (ULONG)(ULONG_PTR)v5->BufferData;

		memcpy((PVOID)v1->Buffer, DllPath->Buffer, DllPath->Length);

		// Copy code
		memcpy(v5, ShellCode, sizeof(ShellCode));

		// Fill stubs
		*(ULONGLONG*)((PUCHAR)v5 + 12) = (ULONGLONG)v1;
		*(ULONGLONG*)((PUCHAR)v5 + 22) = (ULONGLONG)&v5->ModuleHandle;
		*(ULONGLONG*)((PUCHAR)v5 + 32) = (ULONGLONG)LdrLoadDll;
		*(ULONGLONG*)((PUCHAR)v5 + 44) = (ULONGLONG)&v5->Complete;
		*(ULONGLONG*)((PUCHAR)v5 + 60) = (ULONG_PTR)&v5->Status;
		return v5;
	}

	return NULL;
}
PINJECT_BUFFER GetNativeUnloadCode2(IN PVOID ModuleHandle, IN PVOID LdrUnloadDll, IN SIZE_T ViewSize)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PINJECT_BUFFER v5 = NULL;

	UCHAR ShellCode[] =
	{
		0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28   
		0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rcx, ModuleHandle     
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrUnloadDll      
		0xFF, 0xD0,                             // call rax  


		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +31
		0x48, 0xB9, 0x7E, 0x1E, 0x37, 0xC0,0,0,0,0,						// mov rcx,CALL_COMPLETE
		0x48, 0x89, 0x0A,						// mov qword ptr[rdx], rcx  //参数放入v5结构中
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, STATUS_OFFSET   
		0x89, 0x02,                             // mov [rdx], eax
		0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
		0xC3                                    // ret     //fastcall调用约定
	};

	Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &v5, 0, &ViewSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (NT_SUCCESS(Status))
	{
		// Copy code
		memcpy(v5, ShellCode, sizeof(ShellCode));

		// Fill stubs
		*(ULONGLONG*)((PUCHAR)v5 + 6) = (ULONGLONG)(ModuleHandle);

		*(ULONGLONG*)((PUCHAR)v5 + 16) = (ULONGLONG)LdrUnloadDll;

		*(ULONGLONG*)((PUCHAR)v5 + 28) = (ULONGLONG) & ((PINJECT_BUFFER)v5)->Complete;
		*(ULONGLONG*)((PUCHAR)v5 + 51) = (ULONGLONG) & ((PINJECT_BUFFER)v5)->Status;


		return v5;
	}


	return NULL;
}