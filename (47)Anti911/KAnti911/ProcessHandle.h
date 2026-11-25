#pragma once
#include <fltKernel.h>
#include "IoControlRoutine.h"

#ifdef   _WIN64 

#define  _HANDLE_TABLE_  0x200
#define  _OFFSET_        0x10
#define  _OBJECT_BODY_   0x30

typedef struct _HANDLE_TABLE
{
	ULONGLONG TableCode;                                                    //0x0
	PVOID QuotaProcess;														//0x8
	VOID* UniqueProcessId;                                                  //0x10
	ULONG64 HandleLock;														//0x18
	struct _LIST_ENTRY HandleTableList;                                     //0x20
	ULONG64 HandleContentionEvent;											//0x30
	PVOID DebugInfo;														//0x38
	LONG ExtraInfoPages;                                                    //0x40
	union
	{
		ULONG Flags;                                                        //0x44
		UCHAR StrictFIFO : 1;                                                 //0x44
	};
	ULONG FirstFreeHandle;                                                  //0x48
	struct _HANDLE_TABLE_ENTRY* LastFreeHandleEntry;                        //0x50
	ULONG HandleCount;                                                      //0x58
	ULONG NextHandleNeedingPool;                                            //0x5c
	ULONG HandleCountHighWatermark;                                         //0x60
}HANDLE_TABLE, * PHANDLE_TABLE;

typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		VOID* Object;                                                       //0x0
		ULONG ObAttributes;                                                 //0x0
		struct _HANDLE_TABLE_ENTRY_INFO* InfoTable;                         //0x0
		ULONGLONG Value;                                                    //0x0
	};
	union
	{
		ULONG GrantedAccess;                                                //0x8
		struct
		{
			USHORT GrantedAccessIndex;                                      //0x8
			USHORT CreatorBackTraceIndex;                                   //0xa
		};
		ULONG NextFreeTableEntry;                                           //0x8
	};
}HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

#else    
#define  _HANDLE_TABLE_  0x0f4
#define  _OFFSET_        0x8
#define  _OBJECT_BODY_   0x18
typedef  struct _HANDLE_TABLE
{
	ULONG TableCode;                                                        //0x0
	PVOID QuotaProcess;														//0x4
	VOID* UniqueProcessId;                                                  //0x8
	ULONG HandleLock;														//0xc
	struct _LIST_ENTRY HandleTableList;                                     //0x10
	ULONG	HandleContentionEvent;											//0x18
	PVOID   DebugInfo;														//0x1c
	LONG ExtraInfoPages;                                                    //0x20
	union
	{
		ULONG Flags;                                                        //0x24
		UCHAR StrictFIFO : 1;                                               //0x24
	};
	ULONG FirstFreeHandle;                                                  //0x28
	PVOID LastFreeHandleEntry;												//0x2c
	ULONG HandleCount;                                                      //0x30
	ULONG NextHandleNeedingPool;                                            //0x34
	ULONG HandleCountHighWatermark;                                         //0x38
}HANDLE_TABLE, * PHANDLE_TABLE;
typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		VOID* Object;                                                       //0x0
		ULONG ObAttributes;                                                 //0x0
		struct _HANDLE_TABLE_ENTRY_INFO* InfoTable;                         //0x0
		ULONG Value;                                                        //0x0
	};
	union
	{
		ULONG GrantedAccess;                                                //0x4
		struct
		{
			USHORT GrantedAccessIndex;                                      //0x4
			USHORT CreatorBackTraceIndex;                                   //0x6
		};
		ULONG NextFreeTableEntry;                                           //0x4
	};
}HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

#endif



typedef struct _HANDLE_INFORMATION_
{
	ULONG_PTR Handle;
	ULONG_PTR Object;
	ULONG ReferenceCount;
	WCHAR ObjectName[MAX_PATH];
	WCHAR HandleName[MAX_PATH];
}HANDLE_INFORMATION, * PHANDLE_INFORMATION;

typedef struct _HANDLES_INFORMATION_
{
	ULONG NumberOfHandle;
	HANDLE_INFORMATION HandleInfo[1];
}HANDLES_INFORMATION, * PHANDLES_INFORMATION;
typedef struct _COMMUNICATE_PROCESS_HANDLE_
{
	OPERATE_TYPE OperateType;

	ULONG_PTR ProcessIdentity;

	union {

		struct {
			ULONG_PTR Handle;
			ULONG_PTR Object;
			ULONG IsForceKill;
		} Close;

	} u1;

}COMMUNICATE_PROCESS_HANDLE, * PCOMMUNICATE_PROCESS_HANDLE;
NTSTATUS  EnumProcessHandlesByHandleTable(HANDLE ProcessIdentify, PEPROCESS EProcess, PHANDLES_INFORMATION HandlesInfo, ULONG NumberOfHandle);
NTSTATUS HandleTable0(ULONG_PTR TableCode, PEPROCESS EProcess, PHANDLES_INFORMATION HandlesInfo, ULONG NumberOfHandle);
NTSTATUS HandleTable1(ULONG_PTR TableCode, PEPROCESS EProcess, PHANDLES_INFORMATION HandlesInfo, ULONG NumberOfHandle);
NTSTATUS HandleTable2(ULONG_PTR TableCode, PEPROCESS EProcess, PHANDLES_INFORMATION HandlesInfo, ULONG NumberOfHandle);
NTSTATUS HandleTable3(ULONG_PTR TableCode, PEPROCESS EProcess, PHANDLES_INFORMATION HandlesInfo, ULONG NumberOfHandle);

NTSTATUS PsEnumProcessHandles(PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnValue);
NTSTATUS EnumProcessHandlesByService(ULONG_PTR ProcessIdentity, PEPROCESS EProcess, PHANDLES_INFORMATION HandlesInfo, ULONG NumberOfHandle);
VOID InsertHandleToList(PEPROCESS EProcess, HANDLE HandleValue, ULONG_PTR ObjectValue, PHANDLES_INFORMATION HandlesInfo);
VOID ObGetObjectName(HANDLE HandleValue, ULONG_PTR ObjectValue, WCHAR* ObjectName);
VOID ObGetTypeName(HANDLE HandleValue, ULONG_PTR ObjectValue, WCHAR* TypeName);