#include"_tmain.h"
#include "ProcessHelper.h"
#include "ProcessPath.h"
#include "ProcessModule.h"
#include "ProcessHandle.h"
#include "InjectHelper.h"

int _tmain()
{

	//GetProcessPath();
	//ProcessModuleInfo();
	
	EnumProcessHandles();

	//ApcInject();

	//ProtectProcess();
	//HideProcess();
	_tprintf(_T("\r\nInput AnyKey To Exit\r\n"));
	_gettchar();
	_gettchar();
	return 0;
}

void ProcessInfoEx()
{
	vector<PROCESS_INFORMATIONEX>  ProcessInfo;
	ProcessInfo.reserve(100);
	EnumProcess(ProcessInfo);
	_tprintf(_T("ViewSize:%d\r\n"), ProcessInfo.size());
	vector<PROCESS_INFORMATIONEX>::iterator v1;
	for (v1 = ProcessInfo.begin();v1 != ProcessInfo.end();v1++)
	{
		_tprintf(_T("%d     %d\r\n"), v1->ProcessIdentity, v1->ParentPid);
		_tprintf(_T("0x%p\r\n"), v1->EProcess);
		if (v1->ProcessPath)
		{
			wprintf(L"%s\r\n", v1->ProcessPath);
		}
		_tprintf(_T("\r\n\r\n"));
	}

}


void EnumProcessHandles()
{
	vector<HANDLE_INFORMATION>  HandleInfo;
	HandleInfo.reserve(100);
	int i = 0;
	HANDLE ProcessIdentity = 0;
	GetProcessIdentity(_T("Explorer.exe"), &ProcessIdentity);
	EnumProcessHandlesInternal((ULONG_PTR)ProcessIdentity, HandleInfo);
	_tprintf(_T("ViewSize:%d\r\n"), HandleInfo.size());
	vector<HANDLE_INFORMATION>::iterator v1;
	for (v1 = HandleInfo.begin();v1 != HandleInfo.end();v1++)
	{
		_tprintf(_T("%p     %p\r\n"), v1->Handle, v1->Object);

		if (v1->HandleName)
		{
			wprintf(L"%s\r\n", v1->HandleName);
		}
		if (v1->ObjectName)
		{
			wprintf(L"%s\r\n", v1->ObjectName);
		}
		_tprintf(_T("\r\n\r\n"));
		i++;
		if (i % 10 == 0)
		{
			_gettchar();
			_gettchar();
		}
	}

}

