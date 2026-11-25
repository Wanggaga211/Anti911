#include "ProcessHelper.h"
#include "IoControl.h"
#include "ProcessModule.h"

 
BOOL GetProcessIdentity(const TCHAR* ImageName, HANDLE* ProcessIdentity)
{

	HANDLE ToolHelp32Handle = INVALID_HANDLE_VALUE;
	BOOL   IsOk = FALSE;
	PROCESSENTRY32 ProcessEntry32 = { 0 };
	ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);
	//创建一个照相机
	ToolHelp32Handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (ToolHelp32Handle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	IsOk = Process32First(ToolHelp32Handle, &ProcessEntry32);
	do
	{
		if (IsOk)
		{

			if (_tcsicmp(ProcessEntry32.szExeFile, ImageName) == 0)  //查找传入的ImageName
			{
				*ProcessIdentity = (HANDLE)ProcessEntry32.th32ProcessID;
				IsOk = TRUE;
				break;
			}
		}
		else
		{
			break;
		}
		IsOk = Process32Next(ToolHelp32Handle, &ProcessEntry32);
	} while (1);

	if (ToolHelp32Handle != NULL)
	{
		CloseHandle(ToolHelp32Handle);
		ToolHelp32Handle = INVALID_HANDLE_VALUE;
	}
	return IsOk;
}


BOOL EnumProcess(vector<PROCESS_INFORMATIONEX>& ProcessInfo)
{
	OPERATE_TYPE OperateType = ENUM_PROCESS;
	ULONG NumberOfProcess = 1000;
	PPROCESSES_INFORMATION v5 = NULL;
	BOOL IsOk = FALSE;

	ProcessInfo.clear();
	do
	{
		if (v5)
		{
			free(v5);
			v5 = NULL;
		}

		ULONG v7 = sizeof(PROCESSES_INFORMATION) + NumberOfProcess * sizeof(PROCESS_INFORMATIONEX);

		v5 = (PPROCESSES_INFORMATION)malloc(v7);
		memset(v5, 0, v7);

		if (v5)
		{
			IsOk = CommunicateDevice(&OperateType, sizeof(OPERATE_TYPE), (PVOID)v5, v7, NULL);
		}

		NumberOfProcess += 1000;

	} while (!IsOk && GetLastError() == ERROR_INSUFFICIENT_BUFFER);

	if (IsOk && v5->NumberOfProcess > 0)
	{
		NumberOfProcess = v5->NumberOfProcess;

		for (ULONG i = 0; i < NumberOfProcess; i++)
		{
			ProcessInfo.push_back(v5->ProcessInfo[i]);
		}

		IsOk = TRUE;
	}

	if (v5)
	{
		free(v5);
		v5 = NULL;
	}

	return IsOk;
}

BOOL ProtectProcess()
{
	ULONG NumberOfModule = 1000;
	
	BOOL IsOk = FALSE;

	COMMUNICATE_PROTECT_PROCESS v1;
	v1.NumberOfProcess = 0;

	v1.OperateType = PROTECT_PROCESS;
	HANDLE ProcessIdentity = 0;
	GetProcessIdentity(_T("explorer.exe"), &ProcessIdentity);
	v1.ProcessIdentitys[v1.NumberOfProcess++] = ProcessIdentity;
	GetProcessIdentity(_T("taskmgr.exe"), &ProcessIdentity);
	v1.ProcessIdentitys[v1.NumberOfProcess++] = ProcessIdentity;
	do
	{
	
		IsOk = CommunicateDevice(&v1, sizeof(COMMUNICATE_PROTECT_PROCESS),NULL, 0, NULL);



	} while (!IsOk);

	if (IsOk == TRUE)
	{
		_tprintf(_T("ProtectProcess() Success\r\n"));


		_tprintf(_T("Input AnyKey To Remove\r\n"));
		_gettchar();
		_gettchar();
		v1.OperateType = UNPROTECT_PROCESS;
		do
		{

			IsOk = CommunicateDevice(&v1, sizeof(COMMUNICATE_PROTECT_PROCESS), NULL, 0, NULL);



		} while (!IsOk);

		if (IsOk == TRUE)
		{
			_tprintf(_T("RemoveProtectProcess() Success\r\n"));
		}
	}

	return IsOk;
}
BOOL HideProcess()
{
	BOOL IsOk = FALSE;
	COMMUNICATE_HIDE_PROCESS v1;

	v1.OperateType = HIDE_PROCESS;
	HANDLE ProcessIdentity = 0;

	GetProcessIdentity(_T("taskmgr.exe"), &ProcessIdentity);
	v1.ProcessIdentity = ProcessIdentity;
	do
	{

		IsOk = CommunicateDevice(&v1, sizeof(COMMUNICATE_HIDE_PROCESS), NULL, 0, NULL);



	} while (!IsOk);

	if (IsOk == TRUE)
	{
		_tprintf(_T("HideProcess() Success\r\n"));
	}


	return IsOk;
}