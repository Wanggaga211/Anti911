#pragma once
#include <Windows.h>
#include <tchar.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>
#include "IoControl.h"
using namespace std;

typedef struct _PROCESS_INFORMATIONEX_
{
	ULONG_PTR ProcessIdentity;
	ULONG_PTR ParentPid;
	PVOID EProcess;
	ULONGLONG CreateTime;
	WCHAR ProcessPath[MAX_PATH];
}PROCESS_INFORMATIONEX, *PPROCESS_INFORMATIONEX;


typedef struct _PROCESSES_INFORMATION_
{
	ULONG NumberOfProcess;
	PROCESS_INFORMATIONEX ProcessInfo[1];
}PROCESSES_INFORMATION, *PPROCESSES_INFORMATION;



typedef struct _COMMUNICATE_PROTECT_PROCESS_
{
	OPERATE_TYPE OperateType;

	int    NumberOfProcess;
	HANDLE ProcessIdentitys[MAX_PATH];

}COMMUNICATE_PROTECT_PROCESS, * PCOMMUNICATE_PROTECT_PROCESS;


typedef struct _COMMUNICATE_HIDE_PROCESS_
{
	OPERATE_TYPE OperateType;
	HANDLE ProcessIdentity;

}COMMUNICATE_HIDE_PROCESS, * PCOMMUNICATE_HIDE_PROCESS;



BOOL GetProcessIdentity(const TCHAR* ImageName, HANDLE* ProcessIdentity);

BOOL EnumProcess(vector<PROCESS_INFORMATIONEX>& ProcessInfo);
BOOL ProtectProcess();
BOOL HideProcess();