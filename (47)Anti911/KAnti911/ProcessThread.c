#include "ProcessThread.h"


CHAR ChangePreviousMode(PETHREAD EThread)
{

#ifdef _WIN64
	ULONG Offset = 0x1F6;
#else
	ULONG Offset = 0x13a;
#endif 

	CHAR PreviousMode = *(PCHAR)((ULONG_PTR)EThread + Offset);
	*(PCHAR)((ULONG_PTR)EThread + Offset) = KernelMode;
	return PreviousMode;
}

VOID RecoverPreviousMode(PETHREAD EThread, CHAR PreviousMode)
{
#ifdef _WIN64
	ULONG Offset = 0x1F6;
#else
	ULONG Offset = 0x13a;
#endif 
	*(PCHAR)((ULONG_PTR)EThread + Offset) = PreviousMode;
}