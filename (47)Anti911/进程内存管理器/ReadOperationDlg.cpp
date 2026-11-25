// ReadOperationDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "进程内存管理器.h"
#include "ReadOperationDlg.h"
#include "afxdialogex.h"
#include "进程内存管理器Dlg.h"


// CReadOperationDlg 对话框

IMPLEMENT_DYNAMIC(CReadOperationDlg, CDialog)

CReadOperationDlg::CReadOperationDlg(ULONG_PTR ProcessIdentity,CWnd* pParent /*=NULL*/)
	: CDialog(IDD_DIALOG_READ_OPERATION, pParent)
{
	m_ParentDlg = (C进程内存管理器Dlg*)pParent;
	m_ProcessIdentity = ProcessIdentity;
}

CReadOperationDlg::~CReadOperationDlg()
{

}

void CReadOperationDlg::DoDataExchange(CDataExchange* pDX)
{

	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_READ_ADDRESS, m_CEdit_ReadAddress);
	DDX_Control(pDX, IDC_EDIT_READ_DATA, m_CEdit_ReadData);
}


BEGIN_MESSAGE_MAP(CReadOperationDlg, CDialog)

END_MESSAGE_MAP()


// CReadOperationDlg 消息处理程序


BOOL CReadOperationDlg::PreTranslateMessage(MSG* pMsg)
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
		if (pMsg->wParam == VK_RETURN && pMsg->hwnd ==m_CEdit_ReadAddress.m_hWnd)
		{


			ReadVirtualMemory();

			return TRUE;
		}
	}
	return CDialog::PreTranslateMessage(pMsg);
}


BOOL CReadOperationDlg::ReadVirtualMemory()
{
	BOOL  IsOk = FALSE;
	
	UpdateData(TRUE);

	int BufferLength = m_CEdit_ReadAddress.GetWindowTextLength();   //EditBox 上获得数据长度
	if (!BufferLength||BufferLength>16)
	{
		return IsOk;
	}
	CString v1;
	m_CEdit_ReadAddress.GetWindowText(v1);
	_stscanf(v1.GetBuffer(), _T("%p"), &m_BaseAddress);
	if (m_ParentDlg->m_DeviceHandle==INVALID_HANDLE_VALUE||m_ParentDlg->m_DeviceHandle==NULL)
	{
		return IsOk;
	}
	COMMUNICATE_PROCESS_MEMORY v5;

	v5.OperateType = READ_PROCESS_MEMORYS;
	v5.u1.Read.ProcessIdentity = m_ProcessIdentity;
	v5.u1.Read.BaseAddress = m_BaseAddress;
	v5.u1.Read.RegionSize  = m_RegionSize = MAX_LENGTH;

	DWORD ReturnLength = 0;


	memset(m_BufferData, 0, MAX_LENGTH);

	IsOk = DeviceIoControl(m_ParentDlg->m_DeviceHandle, MY_CTL_CODE,
		&v5,
		sizeof(COMMUNICATE_PROCESS_MEMORY),
		m_BufferData,
		MAX_LENGTH,
		&ReturnLength,
		NULL);


	if (IsOk==TRUE)
	{

		CString v1;
		v1 = m_BufferData;
		m_CEdit_ReadData.SetWindowText(v1);
	}


	return IsOk;
}
