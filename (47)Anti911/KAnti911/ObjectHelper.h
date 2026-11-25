#pragma once
#include <fltKernel.h>

typedef enum _OBJECT_INFO_CLASS {
	ObjectBasicInfo,
	ObjectNameInfo,
	ObjectTypeInfo,
	ObjectAllInfo,
	ObjectDataInfo
} OBJECT_INFO_CLASS, * POBJECT_INFO_CLASS;


typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING          TypeName;
	ULONG                   TotalNumberOfHandles;
	ULONG                   TotalNumberOfObjects;
	WCHAR                   Unused1[8];
	ULONG                   HighWaterNumberOfHandles;
	ULONG                   HighWaterNumberOfObjects;
	WCHAR                   Unused2[8];
	ACCESS_MASK             InvalidAttributes;
	GENERIC_MAPPING         GenericMapping;
	ACCESS_MASK             ValidAttributes;
	BOOLEAN                 SecurityRequired;
	BOOLEAN                 MaintainHandleCount;
	USHORT                  MaintainTypeList;
	POOL_TYPE               PoolType;
	ULONG                   DefaultPagedPoolCharge;
	ULONG                   DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;


typedef struct _OBJECT_TYPE_INITIALIZER
{
	UINT16       Length;
	union
	{
		UINT8        ObjectTypeFlags;
		struct
		{
			UINT8        CaseInsensitive : 1;
			UINT8        UnnamedObjectsOnly : 1;
			UINT8        UseDefaultObject : 1;
			UINT8        SecurityRequired : 1;
			UINT8        MaintainHandleCount : 1;
			UINT8        MaintainTypeList : 1;
			UINT8        SupportsObjectCallbacks : 1;
		};
	};
	ULONG32      ObjectTypeCode;
	ULONG32      InvalidAttributes;
	struct _GENERIC_MAPPING GenericMapping;
	ULONG32      ValidAccessMask;
	ULONG32      RetainAccess;
	enum _POOL_TYPE PoolType;
	ULONG32      DefaultPagedPoolCharge;
	ULONG32      DefaultNonPagedPoolCharge;
	PVOID        DumpProcedure;
	PVOID        OpenProcedure;
	PVOID		 CloseProcedure;
	PVOID		 DeleteProcedure;
	PVOID		 ParseProcedure;
	PVOID        SecurityProcedure;
	PVOID		 QueryNameProcedure;
	PVOID		 OkayToCloseProcedure;
}OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;
#ifdef   _WIN64 

typedef struct _OBJECT_TYPE_1
{
	struct _LIST_ENTRY TypeList;
	struct _UNICODE_STRING Name;
	VOID* DefaultObject;
	UINT8        Index;
	UINT8        _PADDING0_[0x3];
	ULONG32      TotalNumberOfObjects;
	ULONG32      TotalNumberOfHandles;
	ULONG32      HighWaterNumberOfObjects;
	ULONG32      HighWaterNumberOfHandles;
	UINT8        _PADDING1_[0x4];
	struct _OBJECT_TYPE_INITIALIZER TypeInfo;
	ULONG64 TypeLock;
	ULONG32      Key;
	UINT8        _PADDING2_[0x4];
	struct _LIST_ENTRY CallbackList;
}OBJECT_TYPE_1, * POBJECT_TYPE_1;

#else
typedef struct _OBJECT_TYPE_1
{
	struct _LIST_ENTRY TypeList;
	struct _UNICODE_STRING Name;
	VOID* DefaultObject;
	UINT8        Index;
	ULONG32      TotalNumberOfObjects;
	ULONG32      TotalNumberOfHandles;
	ULONG32      HighWaterNumberOfObjects;
	ULONG32      HighWaterNumberOfHandles;
	struct _OBJECT_TYPE_INITIALIZER TypeInfo;
	ULONG32 TypeLock;
	ULONG32      Key;
	UINT8        _PADDING2_[0x4];
	struct _LIST_ENTRY CallbackList;
}OBJECT_TYPE_1, * POBJECT_TYPE_1;
#endif

typedef
ULONG_PTR
(*LPFN_OBGETOBJECTTYPE)(PVOID ObjectBody);


typedef
NTSTATUS
(*LPFN_NTQUERYOBJECT)(
	IN HANDLE               ObjectHandle,
	IN OBJECT_INFO_CLASS ObjectInformationClass,
	OUT PVOID               ObjectInformation,
	IN ULONG                Length,
	OUT PULONG              ResultLength);


typedef
NTSTATUS
(*LPFN_NTCLOSE)(
	IN HANDLE  Handle
	);


extern LPFN_OBGETOBJECTTYPE __ObGetObjectType;
extern LPFN_NTQUERYOBJECT   __NtQueryObject;
extern LPFN_NTCLOSE         __NtClose;


void InitializeObjectSource();

