#include "CallbackHelper.h"
#include "ProcessHelper.h"
#include "ObjectHelper.h"
#include "MemoryHelper.h"

PVOID  __FileObjectCallback = NULL;
PVOID  __ProcessObjectCallback = NULL;
void InitializeCallbackSouce(PDRIVER_OBJECT DriverObject)
{
	PLDR_DATA_TABLE_ENTRY LdrDataTableEntry;


	LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	LdrDataTableEntry->Flags |= 0x20;



	FileObjectCallback();
	ProcessObjectCallback();








}

NTSTATUS FileObjectCallback()
{
	NTSTATUS  Status;
	OB_CALLBACK_REGISTRATION  ObCallBackRegistration;
	OB_OPERATION_REGISTRATION ObOperationRegistration;

	//通过文件对象类型进行设置
	POBJECT_TYPE_1  v1 = (POBJECT_TYPE_1)(*IoFileObjectType);
	v1->TypeInfo.SupportsObjectCallbacks = 1;


	memset(&ObCallBackRegistration, 0, sizeof(OB_CALLBACK_REGISTRATION));
	ObCallBackRegistration.Version = ObGetFilterVersion();
	ObCallBackRegistration.OperationRegistrationCount = 1;
	ObCallBackRegistration.RegistrationContext = NULL;
	RtlInitUnicodeString(&ObCallBackRegistration.Altitude, L"File");

	memset(&ObOperationRegistration, 0, sizeof(OB_OPERATION_REGISTRATION)); //初始化结构体变量


	ObOperationRegistration.ObjectType = IoFileObjectType;
	ObOperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;



	ObOperationRegistration.PreOperation = (POB_PRE_OPERATION_CALLBACK)&FileObjectPrevious; //在这里注册一个回调函数指针

	//关联两个结构体
	ObCallBackRegistration.OperationRegistration = &ObOperationRegistration; //注意这一条语句


	Status = ObRegisterCallbacks(&ObCallBackRegistration, &__FileObjectCallback);   //返回值用于卸载对象回调
	if (!NT_SUCCESS(Status))
	{

		Status = STATUS_UNSUCCESSFUL;
	}
	else
	{
		Status = STATUS_SUCCESS;
	}
	return Status;
}
NTSTATUS ProcessObjectCallback()
{
	NTSTATUS  Status;
	OB_CALLBACK_REGISTRATION  ObCallBackRegistration;
	OB_OPERATION_REGISTRATION ObOperationRegistration;

	//通过文件对象类型进行设置
	POBJECT_TYPE_1  v1 = (POBJECT_TYPE_1)(*PsProcessType);
	v1->TypeInfo.SupportsObjectCallbacks = 1;


	memset(&ObCallBackRegistration, 0, sizeof(OB_CALLBACK_REGISTRATION));
	ObCallBackRegistration.Version = ObGetFilterVersion();
	ObCallBackRegistration.OperationRegistrationCount = 1;
	ObCallBackRegistration.RegistrationContext = NULL;
	RtlInitUnicodeString(&ObCallBackRegistration.Altitude, L"Process");

	memset(&ObOperationRegistration, 0, sizeof(OB_OPERATION_REGISTRATION)); //初始化结构体变量


	ObOperationRegistration.ObjectType = PsProcessType;
	ObOperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;



	ObOperationRegistration.PreOperation = (POB_PRE_OPERATION_CALLBACK)&ProcessObjectPrevious; //在这里注册一个回调函数指针
	ObOperationRegistration.PostOperation = NULL;
	//关联两个结构体
	ObCallBackRegistration.OperationRegistration = &ObOperationRegistration; //注意这一条语句


	Status = ObRegisterCallbacks(&ObCallBackRegistration, &__ProcessObjectCallback);   //返回值用于卸载对象回调
	if (!NT_SUCCESS(Status))
	{

		Status = STATUS_UNSUCCESSFUL;
	}
	else
	{
		Status = STATUS_SUCCESS;
	}
	return Status;
}
void UninitializeCallbackSouce()
{
	if (__FileObjectCallback != NULL)
	{
		ObUnRegisterCallbacks(__FileObjectCallback);
	}
	if (__ProcessObjectCallback != NULL)
	{
		ObUnRegisterCallbacks(__ProcessObjectCallback);
	}

}

OB_PREOP_CALLBACK_STATUS FileObjectPrevious(PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION ObPreviousOperationInfo)
{

	UNICODE_STRING v1;
	POBJECT_NAME_INFORMATION ObjectNameInfo;
	PFILE_OBJECT FileObject = (PFILE_OBJECT)ObPreviousOperationInfo->Object;
	HANDLE ProcessIdentify = PsGetCurrentProcessId();

	if (ObPreviousOperationInfo->ObjectType != *IoFileObjectType)
	{
		return OB_PREOP_SUCCESS;
	}
	//过滤无效指针
	if (FileObject->FileName.Buffer == NULL ||
		!MmIsAddressValid(FileObject->FileName.Buffer) ||
		FileObject->DeviceObject == NULL ||
		!MmIsAddressValid(FileObject->DeviceObject))
	{
		return OB_PREOP_SUCCESS;
	}

	if (!NT_SUCCESS(IoQueryFileDosDeviceName((PFILE_OBJECT)FileObject, &ObjectNameInfo)))
	{
		return OB_PREOP_SUCCESS;
	}
	if (ObjectNameInfo->Name.Buffer == NULL || ObjectNameInfo->Name.Length == 0)
	{
		ExFreePool(ObjectNameInfo);
		return OB_PREOP_SUCCESS;
	}

	if (wcsstr(ObjectNameInfo->Name.Buffer, L"D:\\Anti911.txt")
		|| wcsstr(ObjectNameInfo->Name.Buffer, L"C:\\Anti911.txt"))
	{

		if (FileObject->DeleteAccess == TRUE || FileObject->WriteAccess == TRUE)
		{
			if (ObPreviousOperationInfo->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				ObPreviousOperationInfo->Parameters->CreateHandleInformation.DesiredAccess = 0;
			}
			if (ObPreviousOperationInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				ObPreviousOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
			}
		}

	}
	RtlVolumeDeviceToDosName(FileObject->DeviceObject, &v1);
	DbgPrint("ProcessIdentify : %ld File : %wZ  %wZ\r\n", ProcessIdentify, &v1, &ObjectNameInfo->Name);
	ExFreePool(ObjectNameInfo);

	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS ProcessObjectPrevious(PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION ObPreviousOperationInfo)
{
	if (ObPreviousOperationInfo->KernelHandle)
		return OB_PREOP_SUCCESS;

	PEPROCESS EProcess = (PEPROCESS)ObPreviousOperationInfo->Object;
	HANDLE ProcessIdentify = PsGetProcessId(EProcess);



	if (IsProcessIdentifyExist(ProcessIdentify))
	{
		// found in list, remove terminate access
		ObPreviousOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
	}

	return OB_PREOP_SUCCESS;
}