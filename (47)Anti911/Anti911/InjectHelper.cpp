#include "InjectHelper.h"
#include "IoControl.h"
#include "ProcessHelper.h"




BOOL ApcInject()
{
	COMMUNICATE_APC_INJECT v1;

	GetProcessIdentity(_T("explorer.exe"), (HANDLE*)&v1.ProcessIdentity);
	WCHAR  ProcessDirectory[MAX_PATH] = { 0 };

	GetCurrentDirectoryW(MAX_PATH, ProcessDirectory);

#ifdef _WIN64
	wcscpy_s(v1.DllPath, ProcessDirectory);
	wcscat_s(v1.DllPath, _T("\\InjectDll64.dll"));
#else
	wcscpy_s(v1.DllPath, ProcessDirectory);
	wcscat_s(v1.DllPath, _T("\\InjectDll32.dll"));
#endif // _WIN64
	v1.OperateType = APC_INJECT;
	BOOL IsOk = FALSE;
	do
	{

		IsOk = CommunicateDevice(&v1, sizeof(COMMUNICATE_APC_INJECT), NULL, 0, NULL);
	

	} while (!IsOk);

	_tprintf(_T("ApcInject() Success\r\n"));
	return IsOk;


}