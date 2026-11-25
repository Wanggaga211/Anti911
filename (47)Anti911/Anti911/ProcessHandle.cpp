#include "ProcessHandle.h"



BOOL EnumProcessHandlesInternal(ULONG_PTR ProcessIdentity, vector<HANDLE_INFORMATION>& HandleInfo)
{
	HandleInfo.clear();

	ULONG NumberOfHandle = 100;
	PHANDLES_INFORMATION v5 = NULL;
	BOOL IsOk = FALSE;

	COMMUNICATE_PROCESS_HANDLE v1;

	v1.OperateType = ENUM_PROCESS_HANDLES;
	v1.ProcessIdentity = ProcessIdentity;

	do
	{
		ULONG v7 = 0;

		if (v5)
		{
			free(v5);
			v5 = NULL;
		}

		v7 = sizeof(HANDLES_INFORMATION) + NumberOfHandle * sizeof(HANDLE_INFORMATION);
		v5 = (PHANDLES_INFORMATION)malloc(v7);
		memset(v5, 0, v7);
		if (!v5)
		{
			break;
		}
		IsOk = CommunicateDevice(&v1, sizeof(COMMUNICATE_PROCESS_HANDLE), v5, v7, NULL);

		NumberOfHandle = v5->NumberOfHandle + 100;

	} while (!IsOk && GetLastError() == ERROR_INSUFFICIENT_BUFFER);

	if (IsOk && v5->NumberOfHandle > 0)
	{
		for (ULONG i = 0; i < v5->NumberOfHandle; i++)
		{

			HandleInfo.push_back(v5->HandleInfo[i]);
		}
	}

	if (v5)
	{
		free(v5);
		v5 = NULL;
	}

	return IsOk;
}