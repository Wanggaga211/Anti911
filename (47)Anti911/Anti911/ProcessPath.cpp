#include "ProcessPath.h"
#include "ProcessHelper.h"
#include "IoControl.h"


BOOL GetProcessPath()
{
	PROCESS_PATH_REQUEST ProcessPathRequest = { 0 };

	GetProcessIdentity(_T("Taskmgr.exe"), &ProcessPathRequest.ProcessIdentity);

	//通过设备链接名称打开设备对象 获得设备对象句柄
	HANDLE DeviceHandle = CreateFile(SYMBOLIC_LINK,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (DeviceHandle == INVALID_HANDLE_VALUE)
	{
		return 0;
	}



	//发送I/O请求
	DWORD ReturnLength = 0;
	BOOL IsOk = DeviceIoControl(DeviceHandle, CTL_PROCESS_PATH,
		&ProcessPathRequest,						//发送给驱动的数据
		sizeof(PROCESS_PATH_REQUEST),					//发送数据长度
		&ProcessPathRequest,							//驱动返回的数据
		sizeof(PROCESS_PATH_REQUEST),								//返回数据长度 
		&ReturnLength,
		NULL);
	if (IsOk == FALSE)
	{
		int LastError = GetLastError();
		_tprintf(_T("%d\r\n"), LastError);
	}
	else if (IsOk == TRUE)
	{
		wprintf(L"%s", ProcessPathRequest.ProcessPath);
	}

	if (DeviceHandle != NULL)
	{
		CloseHandle(DeviceHandle);
		DeviceHandle = NULL;
	}
}