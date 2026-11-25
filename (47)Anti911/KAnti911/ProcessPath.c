#include "ProcssPath.h"
#include "ProcessHelper.h"
#include "ProcessThread.h"
#include "MemoryHelper.h"
NTSTATUS PsGetProcessPath(PPROCESS_PATH_REQUEST ProcessPathReQuest) {


	NTSTATUS Status = STATUS_SUCCESS;

	PEPROCESS EProcess = NULL;
	if (ProcessPathReQuest->ProcessIdentity == NULL)
	{
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}
	//获取EProcess
	Status = PsLookupProcessByProcessId(ProcessPathReQuest->ProcessIdentity, &EProcess);
	if (Status != STATUS_SUCCESS)
	{
		return Status;
	}
	/*进程对象获取进程完整路径
	if (GetProcessPathByEProcess(EProcess, &ProcessFullPath, MAX_PATH) == TRUE)
	{
		DbgPrint("%S\r\n", ProcessFullPath);
	}*/

	//进程Peb获取进程完整路径
	if (GetProcessPathByPeb(EProcess, ProcessPathReQuest->ProcessPath, MAX_PATH) == TRUE)
	{
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}
BOOLEAN GetProcessPathByEProcess(PVOID EProcess, WCHAR* ProcessFullPath, ULONG ProcessFullPathLength)
{
	BOOLEAN IsOk = FALSE;
	KPROCESSOR_MODE PreviousMode;
	HANDLE ProcessHandle = NULL;
	ULONG HandleAttributes = 0;

	//判断对象的合法   
	if (PsIsRealProcess(EProcess) == TRUE)
	{
		//当前线程的模式
		PreviousMode = PsGetCurrentThreadPreviousMode();
		//x86   0x800007d8    
		//x64   0xffffffff`80000868
		HandleAttributes = (PreviousMode == KernelMode ? OBJ_KERNEL_HANDLE : 0);
		//通过对象体获得对象句柄
		if (NT_SUCCESS(ObOpenObjectByPointer(EProcess, HandleAttributes, NULL, PROCESS_QUERY_INFORMATION,
			*PsProcessType, PreviousMode, &ProcessHandle)))
		{
			PVOID BufferData = NULL;
			ULONG ReturnLength = 0;

			if (ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName,
				BufferData, ReturnLength, &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH)
			{
				if (BufferData = AllocatePoolWithTag(PagedPool, ReturnLength))
				{
					if (NT_SUCCESS(ZwQueryInformationProcess(ProcessHandle,
						ProcessImageFileName, BufferData, ReturnLength, &ReturnLength)))
					{
						HANDLE FileHandle = NULL;
						OBJECT_ATTRIBUTES ObjectAttributes;
						IO_STATUS_BLOCK IoStatusBlock;

						//完整路径:"\Device\HarddiskVolume1\Users\Shine\Desktop\字符转换.exe"
						InitializeObjectAttributes(&ObjectAttributes, (PUNICODE_STRING)BufferData,
							OBJ_CASE_INSENSITIVE | HandleAttributes, NULL, NULL);

						if (NT_SUCCESS(ZwOpenFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
							&ObjectAttributes, &IoStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT)))
						{
							PFILE_OBJECT FileObject;

							//通过句柄获得对象
							if (NT_SUCCESS(ObReferenceObjectByHandle(FileHandle, FILE_READ_ATTRIBUTES,
								*IoFileObjectType, PreviousMode, (PVOID*)&FileObject, NULL)))
							{
								POBJECT_NAME_INFORMATION ObjetNameInfo;

								//通过文件对象获得文件绝对路径
								if (NT_SUCCESS(IoQueryFileDosDeviceName(FileObject, &ObjetNameInfo)))
								{
									//完整路径:"C:\Users\Shine\Desktop\字符转换.exe"
									if (((UNICODE_STRING*)ObjetNameInfo)->MaximumLength < ProcessFullPathLength)
									{
										memcpy(ProcessFullPath, ((UNICODE_STRING*)ObjetNameInfo)->Buffer,
											((UNICODE_STRING*)ObjetNameInfo)->MaximumLength);
									}
									else
									{
										memcpy(ProcessFullPath, ((UNICODE_STRING*)ObjetNameInfo)->Buffer, ProcessFullPathLength);
									}
									if (ObjetNameInfo!=NULL)
									{
										ExFreePool(ObjetNameInfo);
									}	
									IsOk = TRUE;
								}
								ObDereferenceObject(FileObject);
							}
							ZwClose(FileHandle);
						}
					}
					FreePoolWithTag(BufferData);
				}
			}
			ZwClose(ProcessHandle);
		}
	}

	return IsOk;
}
BOOLEAN GetProcessPathByPeb(PVOID EProcess, WCHAR* ProcessFullPath, ULONG ProcessFullPathLength)
{
	BOOLEAN IsOk = TRUE;

	//进程Peb获取进程完整路径
	PPEB Peb = NULL;
	KAPC_STATE  ApcState;

	if (!PsIsRealProcess(EProcess))
	{
		return FALSE;
	}
	Peb = PsGetProcessPeb(EProcess);
	if (Peb == NULL)
	{
		return FALSE;
	}
	KeStackAttachProcess(EProcess, &ApcState);
	__try
	{

		if (Peb->ProcessParameters->ImagePathName.MaximumLength < ProcessFullPathLength)
		{
			memcpy(ProcessFullPath, Peb->ProcessParameters->ImagePathName.Buffer, Peb->ProcessParameters->ImagePathName.MaximumLength);


		}
		else
		{
			memcpy(ProcessFullPath, Peb->ProcessParameters->ImagePathName.Buffer, ProcessFullPathLength);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IsOk = FALSE;
	}

	KeUnstackDetachProcess(&ApcState);


	return IsOk;
}

// ===== Method 3: ProcessImageFileNameWin32 (class 43) =====
// Differences from the other two methods:
//   Method 1 (GetProcessPathByEProcess): ProcessImageFileName -> NT path
//       (\Device\HarddiskVolume1\...) -> ZwOpenFile + IoQueryFileDosDeviceName -> DOS path.
//   Method 2 (GetProcessPathByPeb): KeStackAttachProcess into the target process,
//       read PEB->ProcessParameters->ImagePathName. Needs a context switch.
//   Method 3 (this one): one ZwQueryInformationProcess call returns the DOS path
//       (C://...) directly. No FileObject, no context switch.
// Available on Vista+; verified on the Win7 SP1 x64 lab VM.
// Kept as an independent implementation; PsGetProcessPath still uses Method 2.
#define IMAGE_FILE_NAME_WIN32_CLASS ((PROCESSINFOCLASS)43)

BOOLEAN GetProcessPathByImageFileNameWin32(PVOID EProcess, WCHAR* ProcessFullPath, ULONG ProcessFullPathLength)
{
    BOOLEAN IsOk = FALSE;
    HANDLE ProcessHandle = NULL;
    KPROCESSOR_MODE PreviousMode = KernelMode;
    ULONG HandleAttributes = 0;
    PVOID BufferData = NULL;
    ULONG ReturnLength = 0;
    NTSTATUS Status;

    if (!PsIsRealProcess(EProcess))
        return FALSE;
    if (!ProcessFullPath || ProcessFullPathLength < sizeof(WCHAR))
        return FALSE;

    PreviousMode = PsGetCurrentThreadPreviousMode();
    HandleAttributes = (PreviousMode == KernelMode ? OBJ_KERNEL_HANDLE : 0);

    if (!NT_SUCCESS(ObOpenObjectByPointer(EProcess, HandleAttributes, NULL,
                                          PROCESS_QUERY_INFORMATION,
                                          *PsProcessType, PreviousMode, &ProcessHandle)))
        return FALSE;

    // First call: get the required buffer size.
    Status = ZwQueryInformationProcess(ProcessHandle, IMAGE_FILE_NAME_WIN32_CLASS,
                                       NULL, 0, &ReturnLength);
    if (Status == STATUS_INFO_LENGTH_MISMATCH || Status == STATUS_BUFFER_OVERFLOW)
    {
        if (BufferData = AllocatePoolWithTag(PagedPool, ReturnLength))
        {
            Status = ZwQueryInformationProcess(ProcessHandle, IMAGE_FILE_NAME_WIN32_CLASS,
                                               BufferData, ReturnLength, &ReturnLength);
            if (NT_SUCCESS(Status))
            {
                PUNICODE_STRING ImagePath = (PUNICODE_STRING)BufferData;
                ULONG CopyLength = ImagePath->Length;

                // Leave room for the terminating null character.
                if (CopyLength > ProcessFullPathLength - sizeof(WCHAR))
                    CopyLength = ProcessFullPathLength - sizeof(WCHAR);

                if (ImagePath->Buffer && CopyLength > 0)
                {
                    memcpy(ProcessFullPath, ImagePath->Buffer, CopyLength);
                    ProcessFullPath[CopyLength / sizeof(WCHAR)] = L'\0';
                    IsOk = TRUE;
                }
            }
            FreePoolWithTag(BufferData);
        }
    }

    ZwClose(ProcessHandle);
    return IsOk;
}
