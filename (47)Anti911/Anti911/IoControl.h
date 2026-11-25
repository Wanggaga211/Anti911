#pragma once
#include<Windows.h>
#include<iostream>
#include<tchar.h>


//设备链接名称
#define SYMBOLIC_LINK  _T("\\\\.\\KAnti911")



typedef enum _OPERATE_TYPE_
{
	UNKNOWN = 0,
	ENUM_PROCESS,						// 枚举进程
	PROTECT_PROCESS,
	UNPROTECT_PROCESS,
	CLEAR_PROTECT_PROCESS,
	HIDE_PROCESS,
	ENUM_PROCESS_MODULES,
	DUMP_PROCESS_MODULE,
	UNLOAD_PROCESS_MODULE,
	ENUM_PROCESS_HANDLES,


	APC_INJECT,
	SERVICE_MAX
} OPERATE_TYPE;


#define CTL_BASE          0x800
#define CTL_CODE_NEITHER(i)		    \
		CTL_CODE					\
		(							\
			FILE_DEVICE_UNKNOWN,	\
			CTL_BASE + i + 0x100,	\
			METHOD_NEITHER,			\
			FILE_ANY_ACCESS			\
		)

#define MY_CTL_CODE    CTL_CODE_NEITHER(1)



//I/O控制码 从0x830往后递增
#define CTL_THREAD_INJECT \
	CTL_CODE(FILE_DEVICE_UNKNOWN,0x830,METHOD_BUFFERED,FILE_ANY_ACCESS)


#define CTL_PROCESS_PATH \
	CTL_CODE(FILE_DEVICE_UNKNOWN,0x840,METHOD_BUFFERED,FILE_ANY_ACCESS)


BOOL CommunicateDevice(
	PVOID InputBuffer,
	DWORD InputBufferViewSize,
	PVOID OutputBuffer,
	DWORD OutputBufferViewSize,
	DWORD* ReturnValue
);

