#include "ProcessModule.h"
#include "ProcessHelper.h"
void ProcessModuleInfo()
{
	vector<MODULE_INFORMATION>  ModuleInfo;
	ModuleInfo.reserve(100);
	int i = 0;
	HANDLE ProcessIdentity = 0;
	GetProcessIdentity(_T("Explorer.exe"), &ProcessIdentity);
	EnumProcessModules((ULONG_PTR)ProcessIdentity, ModuleInfo);
	_tprintf(_T("ViewSize:%d\r\n"), ModuleInfo.size());
	vector<MODULE_INFORMATION>::iterator v1;
	for (v1 = ModuleInfo.begin();v1 != ModuleInfo.end();v1++)
	{
		_tprintf(_T("%p     %d\r\n"), v1->ModuleBase, v1->SizeOfImage);

		if (v1->ModulePath)
		{
			wprintf(L"%s\r\n", v1->ModulePath);
		}
		_tprintf(_T("\r\n\r\n"));
		i++;
		if (i % 10 == 0)
		{
			//_gettchar();
			//_gettchar();
		}
	}
	v1 = ModuleInfo.begin();
	//DumpProcessModule((ULONG_PTR)ProcessIdentity, v1[0].ModuleBase, v1[0].SizeOfImage);

	if (UnloadProcessModule((ULONG_PTR)ProcessIdentity, v1[2].ModuleBase) == TRUE)
	{
		wprintf(L"%s\r\n", v1[2].ModulePath);
		_tprintf(_T("UnloadProcessModule() Success\r\n"));
	}

}


BOOL EnumProcessModules(ULONG_PTR ProcessIdentity,vector<MODULE_INFORMATION>& ModuleInfo)
{
	ModuleInfo.clear();

	ULONG NumberOfModule = 1000;
	PMODULES_INFORMATION v5 = NULL;
	BOOL IsOk = FALSE;

	COMMUNICATE_PROCESS_MODULE v1;

	v1.OperateType = ENUM_PROCESS_MODULES;
	v1.ProcessIdentity = ProcessIdentity;
	
	do
	{
		ULONG v7 = 0;

		if (v5)
		{
			free(v5);
			v5 = NULL;
		}

		v7 = sizeof(MODULES_INFORMATION) + NumberOfModule * sizeof(MODULE_INFORMATION);
		v5 = (PMODULES_INFORMATION)malloc(v7);
		memset(v5, 0, v7);
		if (!v5)
		{
			break;
		}
		IsOk = CommunicateDevice(&v1, sizeof(COMMUNICATE_PROCESS_MODULE), v5, v7, NULL);

		NumberOfModule = v5->NumberOfModule + 100;

	} while (!IsOk && GetLastError() == ERROR_INSUFFICIENT_BUFFER);

	if (IsOk && v5->NumberOfModule > 0)
	{
		for (ULONG i = 0; i < v5->NumberOfModule; i++)
		{
			MODULE_INFORMATION v4;

			v4.ModuleBase = v5->ModuleInfo[i].ModuleBase;
			v4.SizeOfImage = v5->ModuleInfo[i].SizeOfImage;
			
			wcsncpy_s(v4.ModulePath, MAX_PATH, v5->ModuleInfo[i].ModulePath, MAX_PATH);

			ModuleInfo.push_back(v4);
		}
	}

	if (v5)
	{
		free(v5);
		v5 = NULL;
	}

	return IsOk;
}
void DumpProcessModule(ULONG_PTR ProcessIdentity, ULONG_PTR ModuleBase, ULONG SizeOfImage)
{
	PVOID v5 = NULL;

	if ((ProcessIdentity == 0 && SizeOfImage == 0) || SizeOfImage == 0)
	{
		return;
	}

	v5 = malloc(SizeOfImage);
	if (!v5)
	{
		return;
	}

	COMMUNICATE_PROCESS_MODULE v1;

	v1.u1.Dump.ModuleBase = ModuleBase;
	v1.u1.Dump.SizeOfImage = SizeOfImage;
	v1.ProcessIdentity = ProcessIdentity;
	v1.OperateType = DUMP_PROCESS_MODULE;

	BOOL IsOk = CommunicateDevice(&v1, sizeof(COMMUNICATE_PROCESS_MODULE), v5, SizeOfImage, NULL);


	if (v5!=NULL)
	{
		free(v5);

		v5 = NULL;
	}

}
BOOL UnloadProcessModule(ULONG_PTR ProcessIdentity, ULONG_PTR ModuleBase)
{
	if (ProcessIdentity == 0)
	{
		return FALSE;
	}

	COMMUNICATE_PROCESS_MODULE v1;
	v1.u1.Unload.ModuleBase = ModuleBase;
	v1.u1.Unload.LdrpHashTable = 0;
	v1.ProcessIdentity = ProcessIdentity;
	v1.OperateType = UNLOAD_PROCESS_MODULE;

	return CommunicateDevice(&v1, sizeof(COMMUNICATE_PROCESS_MODULE), NULL, 0, NULL);
}