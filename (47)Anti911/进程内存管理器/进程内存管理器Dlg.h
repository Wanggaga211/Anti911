
// 进程内存管理器Dlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include <WinIoCtl.h>
#include <afxtempl.h>
#include <vector>

using namespace std;
#define CTL_BASE          0x800
#define CTL_CODE_NEITHER(i)		    \
		CTL_CODE					\
		(							\
			FILE_DEVICE_UNKNOWN,	\
			CTL_BASE + i + 0x100,	\
			METHOD_NEITHER,			\
			FILE_ANY_ACCESS			\
		)

#define MY_CTL_CODE    CTL_CODE_NEITHER(1)


enum OPERATE_TYPE
{
	ENUM_PROCESS_MEMORYS = 10,
	READ_PROCESS_MEMORYS = 11,
	WRITE_PROCESS_MEMORYS = 12,
	MODIFY_PROCESS_MEMORYS = 13
};

typedef struct _COMMUNICATE_PROCESS_MEMORY_
{
	OPERATE_TYPE OperateType;

	union {
		struct {
			ULONG_PTR ProcessIdentity;
		} Query;

		struct
		{
			PVOID      BaseAddress;
			SIZE_T     RegionSize;
			ULONG_PTR      ProcessIdentity;
		}Read;
		struct
		{
			PVOID      BaseAddress;
			SIZE_T     RegionSize;
			ULONG_PTR      ProcessIdentity;
			char* BufferData;
		}Write;

		struct 
		{
			ULONG_PTR       ProcessIdentity;
			PVOID       BaseAddress;
			SIZE_T      RegionSize;
			ULONG       NewProtect;
			ULONG       OldProtect;
		}Modify;
	} u1;
}COMMUNICATE_PROCESS_MEMORY, * PCOMMUNICATE_PROCESS_MEMORY;

typedef struct _MEMORY_INFORMATION_
{
	PVOID     BaseAddress;
	SIZE_T    RegionSize;
	ULONG     Protect;
	ULONG     State;
	ULONG     Type;
}MEMORY_INFORMATION, * PMEMORY_INFORMATION;

typedef struct _MEMORYS_INFORMATION_
{
	ULONG NumberOfMemory;
	MEMORY_INFORMATION MemoryInfo[1];
}MEMORYS_INFORMATION, *PMEMORYS_INFORMATION;



// C进程内存管理器Dlg 对话框
class C进程内存管理器Dlg : public CDialogEx
{
// 构造
public:
	C进程内存管理器Dlg(CWnd* pParent = NULL);	// 标准构造函数
	~C进程内存管理器Dlg()
	{
		m_Vectors.clear();
		if (m_DeviceHandle!=NULL)
		{
			CloseHandle(m_DeviceHandle);
			m_DeviceHandle = NULL;
		}
	}

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_MAIN };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_CListCtrl_ProcessMemorys;
	UINT m_CEdit_ProcessIdentity;
	HANDLE m_DeviceHandle;
	PVOID  m_BaseAddress;
	SIZE_T m_RegionSize;
	ULONG  m_NewProtect;
	ULONG  m_OldProtect;  //数据库

	afx_msg void OnBnClickedOk();
	BOOL C进程内存管理器Dlg::QueryVirtualMemory();
	BOOL C进程内存管理器Dlg::VirtualProtect();
    BOOL OpenDeviceObject(LPCTSTR DeviceFullPathData)
	{
		m_DeviceHandle = CreateFile(DeviceFullPathData,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (m_DeviceHandle == INVALID_HANDLE_VALUE)
		{
			return FALSE;
		}

		return TRUE;

	}
	BOOL SendIoControlCode(ULONG32 IoControlCode);
	VOID C进程内存管理器Dlg::AddItemToControlList(MEMORY_INFORMATION MemoryInfo);
	VOID C进程内存管理器Dlg::InitSolidMenu();

private:
	vector<MEMORY_INFORMATION> m_Vectors;
	
public:
	afx_msg void OnMemoryReadOperation();
	afx_msg void OnMemoryWriteOperation();
	afx_msg void OnNMRClickListProcessMemory(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnProtectNoAccess();
	afx_msg void OnProtectRead();
	afx_msg void OnProtectReadWrite();
	afx_msg void OnProtectReadWriteGuard();
	afx_msg void OnProtectReadExecute();
	afx_msg void OnProtectWriteCopy();
	afx_msg void OnProtectRecover();
};
