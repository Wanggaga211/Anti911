#pragma once
#include <fltKernel.h>


//驱动对象名称
#define DEVICE_NAME L"\\Device\\KAnti911"
//设备链接名称
#define SYMBOLIC_LINK L"\\DosDevices\\KAnti911"

#define MAX_PATH	260




typedef struct _DEVICE_EXTENSION_
{
	PDEVICE_OBJECT DeviceObject;
	UNICODE_STRING SymbolicLink;
}DEVICE_EXTENSION,*PDEVICE_EXTENSION;


//通用派遣例程
NTSTATUS DispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp);
//驱动卸载派遣例程
void DriverUnload(PDRIVER_OBJECT DriverObject);
//设备控制派遣例程
NTSTATUS IoControlRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp);





