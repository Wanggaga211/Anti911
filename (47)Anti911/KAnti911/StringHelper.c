#include "SystemHelper.h"

//×Ö·û´®µÄ³õÊ¼»¯
void InitializeString()
{
	ANSI_STRING v1;
	RtlInitAnsiString(&v1, "HelloAnsiString");

	char Stack1[0x1000] = "HelloAnsiString";
	RtlInitUnicodeString(&v1, Stack1);


	PCHAR Heap1 = (PWCHAR)ExAllocatePool(NonPagedPool, 0x1000);
	if (Heap1 != NULL)
	{
		strcpy(Heap1, "HelloAnsiString");
	}
	RtlInitUnicodeString(&v1, Heap1);
	KdPrint(("%Z\n", &v1));
	RtlFreeAnsiString(&v1);
	Heap1 = NULL;



	UNICODE_STRING v2;
	RtlInitUnicodeString(&v2, L"HelloUnicodeString");

	WCHAR Stack2[0x1000] = L"HelloUnicodeString";
	RtlInitUnicodeString(&v2, Stack2);



	PWCHAR Heap2 = (PWCHAR)ExAllocatePool(NonPagedPool, 0x1000);
	if (Heap2 != NULL)
	{
		wcscpy(Heap2, L"HelloUnicodeString");
	}
	RtlInitUnicodeString(&v2, Heap2);
	RtlFreeUnicodeString(&v2);
	Heap2 = NULL;
	KdPrint(("%wZ\n", &v2));
}



void UnicodeString2AnsiString()
{
	UNICODE_STRING v1;
	RtlInitUnicodeString(&v1, L"HelloWorld");

	ANSI_STRING v2;
	NTSTATUS Status = RtlUnicodeStringToAnsiString(&v2, &v1, TRUE);
	if (NT_SUCCESS(Status))
	{
		KdPrint(("%Z\n", &v2));
	}
	else
	{
		
	}
	RtlFreeAnsiString(&v2);
}

void AnsiString2UnicodeString()
{
	ANSI_STRING v1;
	RtlInitString(&v1, "HelloWorld");
	UNICODE_STRING v2;
	NTSTATUS Status = RtlAnsiStringToUnicodeString(&v2, &v1, TRUE);

	if (NT_SUCCESS(Status))
	{
		
		KdPrint(("%wZ\n", &v2));
	}
	else
	{
	}
	RtlFreeUnicodeString(&v2);
}





NTSTATUS UnicodeStringCopy2UnicodeString(OUT PUNICODE_STRING DestinationString,
	IN PUNICODE_STRING SourceString)
{
	ASSERT(DestinationString != NULL && SourceString != NULL);
	if (DestinationString == NULL || SourceString == NULL || SourceString->Buffer == NULL)
		return STATUS_INVALID_PARAMETER;
	if (SourceString->Length == 0)
	{
		DestinationString->Length = DestinationString->MaximumLength = 0;
		DestinationString->Buffer = NULL;
		return STATUS_SUCCESS;
	}

	DestinationString->Buffer = ExAllocatePool(PagedPool, SourceString->MaximumLength);
	DestinationString->Length = SourceString->Length;
	DestinationString->MaximumLength = SourceString->MaximumLength;

	memcpy(DestinationString->Buffer, SourceString->Buffer, SourceString->Length);

	return STATUS_SUCCESS;
}

ULONG SearchPattern1(PUCHAR PatternValue, ULONG PatternValueLength, PUCHAR VirtualAddress, ULONG ViewSize)
{

	ULONG i = 0;
	PUCHAR v1 = VirtualAddress;
	UCHAR v5[0x100];
	if (ViewSize <= 0)
		return -1;

	memset(v5, PatternValueLength + 1, 0x100);
	for (i = 0; i < PatternValueLength; i++)
	{
		v5[PatternValue[i]] = (UCHAR)(PatternValueLength - i);
	}

	while (v1 + PatternValueLength <= VirtualAddress + ViewSize)
	{
		UCHAR* m = PatternValue, * n = v1;
		ULONG i = 0;
		for (i = 0; i < PatternValueLength; i++)
		{
			if (m[i] != n[i])
				break;
		}
		if (i == PatternValueLength)
			return (ULONG)v1;
		if (v1 + PatternValueLength == VirtualAddress + ViewSize)
			return -1;
		v1 += v5[v1[PatternValueLength]];
	}
	return -1;
}



NTSTATUS SearchPattern2(IN PUCHAR PatternValue, IN UCHAR Keyword,
	IN ULONG_PTR PatternValueLength, IN const VOID* VirtualAddress, IN ULONG_PTR ViewSize, OUT PVOID* Position)
{
	if (Position == NULL || PatternValue == NULL || VirtualAddress == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < ViewSize - PatternValueLength; i++)
	{
		BOOLEAN IsOk = TRUE;
		for (ULONG_PTR j = 0; j < PatternValueLength; j++)
		{
			if (PatternValue[j] != Keyword && PatternValue[j] != ((PUCHAR)VirtualAddress)[i + j])
			{
				IsOk = FALSE;
				break;
			}
		}

		if (IsOk != FALSE)
		{
			*Position = (PUCHAR)VirtualAddress + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

ULONG CmpAndGetStringLength(PUNICODE_STRING UnicodeString, ULONG Length)
{
	ULONG v1 = 0;
	v1 = Length > UnicodeString->Length / sizeof(WCHAR) ? UnicodeString->Length / sizeof(WCHAR) : Length - 1;
	return v1;
}

BOOLEAN IsUnicodeStringValid(PUNICODE_STRING UnicodeString)
{
	BOOLEAN IsOk = FALSE;

	__try
	{
		if (UnicodeString->Length > 0 &&
			UnicodeString->Buffer &&
			MmIsAddressValid(UnicodeString->Buffer) &&
			MmIsAddressValid(&UnicodeString->Buffer[UnicodeString->Length / sizeof(WCHAR) - 1]))
		{
			IsOk = TRUE;
		}

	}
	__except (1)
	{
		
		IsOk = FALSE;
	}

	return IsOk;
}
