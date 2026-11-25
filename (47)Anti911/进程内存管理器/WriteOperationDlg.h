#pragma once

#include "进程内存管理器Dlg.h"


// CWriteOperationDlg 对话框

class CWriteOperationDlg : public CDialog
{
	DECLARE_DYNAMIC(CWriteOperationDlg)
private:
	C进程内存管理器Dlg* m_ParentDlg = NULL;
	ULONG32 m_ProcessIdentity = 0;
	PVOID   m_BaseAddress;
	SIZE_T  m_RegionSize;
public:
	CWriteOperationDlg(ULONG_PTR ProcessIdentity,CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CWriteOperationDlg();
	char* Wchar2Char(WCHAR* SourceString);
	char* Char2Char(CHAR* SourceString);
public:
	CEdit m_CEdit_WriteAddress;
	CEdit m_CEdit_WriteData;
// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_WRITE_OPERATION };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	DECLARE_MESSAGE_MAP()
public:
	BOOL WriteVirtualMemory();
	virtual BOOL PreTranslateMessage(MSG* pMsg);
};
