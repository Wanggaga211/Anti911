#pragma once
#include <fltKernel.h>

NTSTATUS UnicodeStringCopy2UnicodeString(OUT PUNICODE_STRING DestinationString,
	IN PUNICODE_STRING SourceString);
ULONG SearchPattern1(PUCHAR PatternValue, ULONG PatternValueLength, PUCHAR VirtualAddress, ULONG ViewSize);
NTSTATUS SearchPattern2(IN PUCHAR PatternValue, IN UCHAR Keyword,
	IN ULONG_PTR PatternValueLength, IN const VOID* VirtualAddress, IN ULONG_PTR ViewSize, OUT PVOID* Position);

ULONG CmpAndGetStringLength(PUNICODE_STRING UnicodeString, ULONG Length);
BOOLEAN IsUnicodeStringValid(PUNICODE_STRING UnicodeString);


