#include "DriverEntry.h"
#include "SystemHelper.h"
#include "IoControlRoutine.h"
#include "ThreadInject.h"
#include "HookHelper.h"
#include "SystemHelper.h"
#include "KiFastCall.h"
#include "StackBackTrace.h"
#include "ObjectHelper.h"
#include "ProcssPath.h"
#include "ProcessHandle.h"
#include "StackBackTrace.h"
#include "ApcInject.h"
#include "CallbackHelper.h"
#include "Common.h"





//bp KAnti911!DriverEntry
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{

	UNREFERENCED_PARAMETER(RegisterPath);

	NTSTATUS Status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject;
	UNICODE_STRING DeviceName;
	UNICODE_STRING SymbolicLink;
	PDEVICE_EXTENSION DeviceExtension = NULL;

	DriverObject->DriverUnload = DriverUnload;
	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&SymbolicLink, SYMBOLIC_LINK);

	Status = IoCreateDevice(DriverObject,	//驱动对象
		sizeof(DEVICE_EXTENSION),									//设备扩展
		&DeviceName,					    //设备名称
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&DeviceObject);						//设备对象
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	//设备对象名称关联链接名称
	Status = IoCreateSymbolicLink(&SymbolicLink, &DeviceName);
	if (!NT_SUCCESS(Status))
	{
		//关闭设备对象
		IoDeleteDevice(DeviceObject);
		return Status;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = DispatchRoutine;
	}

	//设备控制派遣例程
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlRoutine;

	DeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	DeviceExtension->DeviceObject = DeviceObject;
	DeviceExtension->SymbolicLink = SymbolicLink;


	InitializeProcessSource();
	InitializeCallbackSouce(DriverObject);


	__Hooks = InitializeHookSource(100);  //Hook数据结构
	InitializeSystemSource();
	InitializeObjectSource();              //对象资源初始化
	//InstallSsdtHook();
	//InstallInlineHook();
	//InstallKiFastCallHook();    //重载内核

#ifdef _WIN64
	StackBackTrace();
#else
	//GetKiFastCall();    //栈回溯测试
#endif // _WIN64

	
	return Status;
}
//驱动卸载派遣例程
void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	DbgPrint("DriverUnload()\r\n");

	UNICODE_STRING SymbolicLink;
	PDEVICE_OBJECT DeviceObject = NULL;
	PDEVICE_EXTENSION DeviceExtension = NULL;
	UninitializeHookSource(__Hooks);  //销毁Hook
	//销毁设备链接名称
	RtlInitUnicodeString(&SymbolicLink, SYMBOLIC_LINK);
	

	//从驱动对象获得设备对象链表头结点
	DeviceObject = DriverObject->DeviceObject;
	//销毁设备对象链表中的所有设备对象
	while (DeviceObject != NULL)
	{
		DeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
		DeviceObject = DeviceObject->NextDevice;
		IoDeleteSymbolicLink(&DeviceExtension->SymbolicLink);
		IoDeleteDevice(DeviceExtension->DeviceObject);
	}
	UninitializeSystemSource();
	UninitializeCallbackSouce();





}
//通用派遣例程
NTSTATUS DispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
//设备控制派遣例程
NTSTATUS IoControlRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;

	//通过Irp获得Irp堆栈
	PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	
	//取得I/O控制代码
	ULONG IoControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;

	//取得I/O缓冲区指针和缓冲区长度(从Ring3发送过来的数据)
	PVOID InputBuffer = Irp->AssociatedIrp.SystemBuffer;
	PVOID OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
	ULONG InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;

	ULONG OutputBufferLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

	//判断I/O控制码
	switch (IoControlCode)
	{
	case CTL_THREAD_INJECT:
	{
		INJECT_REQUEST  InjectRequest = { 0 };
		__try
		{
			if (InputBufferLength == sizeof(INJECT_REQUEST))
			{

				if (InputBuffer != NULL)
				{
					memcpy(&InjectRequest, InputBuffer, InputBufferLength);
				}
			}

			Status = ThreadInject(InjectRequest, InputBufferLength);   //线程注入

			if (!NT_SUCCESS(Status))
			{
				Irp->IoStatus.Information = 0;
				break;
			}
			Irp->IoStatus.Information = OutputBufferLength;
			break;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Irp->IoStatus.Information = 0;
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
	}
	
	case CTL_PROCESS_PATH:
	{
		PROCESS_PATH_REQUEST  ProcessPathRequest = { 0 };
		__try
		{
			if (InputBufferLength == sizeof(ProcessPathRequest) && OutputBufferLength == sizeof(ProcessPathRequest))
			{

				if (InputBuffer != NULL)
				{
					memcpy(&ProcessPathRequest, InputBuffer, InputBufferLength);
				}
			}

			Status = PsGetProcessPath(&ProcessPathRequest);   //线程注入

			if (!NT_SUCCESS(Status))
			{
				Irp->IoStatus.Information = 0;
				break;
			}

			memcpy(OutputBuffer, &ProcessPathRequest, sizeof(PROCESS_PATH_REQUEST));
			Irp->IoStatus.Information = sizeof(PROCESS_PATH_REQUEST);
			break;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Irp->IoStatus.Information = 0;
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
	}
	case MY_CTL_CODE:
	{
		PVOID OutputBuffer = Irp->UserBuffer;
		PVOID InputBuffer = IoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
		ULONG InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		ULONG OutputBufferLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
		ULONG ReturnValue = 0;
		Status = CommunicatNeitherControl(InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, &ReturnValue);

		Irp->IoStatus.Information = ReturnValue;
		break;
	}
	default:
	{	
		Irp->IoStatus.Information = 0;
	
		break;
	}
	}

	//完成请求(将Irp数据包还给I/O管理器)
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}
