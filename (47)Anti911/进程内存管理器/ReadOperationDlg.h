#pragma once
#include "afxwin.h"
#include "进程内存管理器Dlg.h"

// CReadOperationDlg 对话框
#define MAX_LENGTH 20
class CReadOperationDlg : public CDialog
{
	DECLARE_DYNAMIC(CReadOperationDlg)

public:
	CReadOperationDlg(ULONG_PTR ProcessIdentity,CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CReadOperationDlg();

private:
	ULONG_PTR m_ProcessIdentity = 0;
	PVOID   m_BaseAddress;
	SIZE_T  m_RegionSize;
	CHAR    m_BufferData[MAX_LENGTH];
	C进程内存管理器Dlg* m_ParentDlg = NULL;


// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_READ_OPERATION };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	BOOL ReadVirtualMemory();
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	CEdit m_CEdit_ReadAddress;
	CEdit m_CEdit_ReadData;



};
