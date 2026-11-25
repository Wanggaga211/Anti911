// WriteOperationDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "进程内存管理器.h"
#include "WriteOperationDlg.h"
#include "afxdialogex.h"
#include "进程内存管理器Dlg.h"


// CWriteOperationDlg 对话框

IMPLEMENT_DYNAMIC(CWriteOperationDlg, CDialog)

CWriteOperationDlg::CWriteOperationDlg(ULONG_PTR ProcessIdentity,CWnd* pParent /*=NULL*/)
	: CDialog(IDD_DIALOG_WRITE_OPERATION, pParent)
{
	m_ParentDlg = (C进程内存管理器Dlg*)pParent;
	m_ProcessIdentity = ProcessIdentity;
}

CWriteOperationDlg::~CWriteOperationDlg()
{
}

void CWriteOperationDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_WRITE_ADDRESS, m_CEdit_WriteAddress);
	DDX_Control(pDX, IDC_EDIT_WRITE_DATA, m_CEdit_WriteData);
}


BEGIN_MESSAGE_MAP(CWriteOperationDlg, CDialog)
END_MESSAGE_MAP()


// CWriteOperationDlg 消息处理程序


BOOL CWriteOperationDlg::PreTranslateMessage(MSG* pMsg)
{
	// TODO: 在此添加专用代码和/或调用基类
	if (pMsg->message == WM_KEYDOWN)
	{
		// 屏蔽VK_ESCAPE、VK_DELETE
		if (pMsg->wParam == VK_ESCAPE)
		{
			PostMessage(WM_CLOSE);
			return true;
		}

		//如果是可编辑框的回车键
		if ((pMsg->wParam == VK_RETURN && pMsg->hwnd == m_CEdit_WriteData.m_hWnd )
			||( pMsg->wParam == VK_RETURN && pMsg->hwnd == m_CEdit_WriteAddress.m_hWnd))
		{


			WriteVirtualMemory();

			return TRUE;
		}
	}
	return CDialog::PreTranslateMessage(pMsg);
}


BOOL CWriteOperationDlg::WriteVirtualMemory()
{
	BOOL  IsOk = FALSE;

	UpdateData(TRUE);

	int BufferLength = m_CEdit_WriteAddress.GetWindowTextLength();   //EditBox 上获得数据长度
	if (!BufferLength || BufferLength > 16)
	{
		return IsOk;
	}
	CString v1;
	m_CEdit_WriteAddress.GetWindowText(v1);
	_stscanf(v1.GetBuffer(), _T("%p"), &m_BaseAddress);


	 BufferLength = m_CEdit_WriteData.GetWindowTextLength();
	if (m_ParentDlg->m_DeviceHandle == INVALID_HANDLE_VALUE || m_ParentDlg->m_DeviceHandle == NULL)
	{
		return IsOk;
	}
	
	PCOMMUNICATE_PROCESS_MEMORY v5;
	v5 = (PCOMMUNICATE_PROCESS_MEMORY)malloc(sizeof(COMMUNICATE_PROCESS_MEMORY)+BufferLength);
	if (v5 == NULL)
	{
		return FALSE;
	}
	memset(v5, 0, sizeof(COMMUNICATE_PROCESS_MEMORY)+BufferLength);
	v5->OperateType = WRITE_PROCESS_MEMORYS;
	v5->u1.Write.BaseAddress = m_BaseAddress;
	v5->u1.Write.RegionSize =  BufferLength;
	v5->u1.Write.ProcessIdentity = m_ProcessIdentity;
	v5->u1.Write.BufferData = (char*)(v5+1);


	DWORD ReturnLength = 0;

	m_CEdit_WriteData.GetWindowText(v1);
#ifdef _UNICODE
	char* v2 = Wchar2Char(v1.LockBuffer());
#else
	char* v2 = v1.Char2Char();
#endif // _UNICODE



	if (v2 != NULL)
	{
		memcpy(v5->u1.Write.BufferData,v2, v5->u1.Write.RegionSize);
		delete v2;
		v2 = NULL;
	}
	IsOk = DeviceIoControl(m_ParentDlg->m_DeviceHandle, MY_CTL_CODE,
		v5,
		sizeof(COMMUNICATE_PROCESS_MEMORY)+BufferLength,
		NULL,
		0,
		&ReturnLength,
		NULL);

	if (v5 != NULL)
	{

		free(v5);
		v5 = NULL;
	}
	return IsOk;
}


char* CWriteOperationDlg::Wchar2Char(WCHAR* SourceString)
{

	char* v5 = NULL;
	ULONG v7 = 0;

	if (SourceString != NULL)
	{
		v7 = WideCharToMultiByte(CP_ACP, NULL, SourceString, -1, NULL, 0, NULL, FALSE);

		v5 = new char[v7 + 1];

		if (v5 == NULL)
		{
			return NULL;
		}
		memset(v5, 0, v7 + 1);

		WideCharToMultiByte(CP_OEMCP, NULL, SourceString, -1, v5, v7, NULL, FALSE);
	}

	return v5;
}

char* CWriteOperationDlg::Char2Char(CHAR* SourceString)
{
	char* v5 = NULL;
	ULONG v7 = 0;
	


	if (SourceString != NULL)
	{
		v7 = strlen(SourceString);

		v5 = new char[v7 + 1];

		if (v5 == NULL)
		{
			return NULL;
		}
		memset(v5, 0, v7 + 1);

		memcpy(v5, SourceString, v7);
	}

	return v5;
}