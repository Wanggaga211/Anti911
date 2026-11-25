
// 进程内存管理器Dlg.cpp : 实现文件
//

#include "stdafx.h"
#include "进程内存管理器.h"
#include "进程内存管理器Dlg.h"
#include "afxdialogex.h"
#include "ReadOperationDlg.h"
#include "WriteOperationDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// C进程内存管理器Dlg 对话框
C进程内存管理器Dlg::C进程内存管理器Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_MAIN, pParent)
	, m_CEdit_ProcessIdentity(0)
{

	m_DeviceHandle = NULL;
	m_BaseAddress = NULL;
    m_RegionSize = 0;
	m_OldProtect = 0;
	m_NewProtect = 0;
	//请求Ring0设备对象
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void C进程内存管理器Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_PROCESS_MEMORY, m_CListCtrl_ProcessMemorys);
	DDX_Text(pDX, IDC_EDIT_PROCESS_ID, m_CEdit_ProcessIdentity);
}

BEGIN_MESSAGE_MAP(C进程内存管理器Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &C进程内存管理器Dlg::OnBnClickedOk)
	ON_COMMAND(ID_MEMORY_READ_OPERATION, &C进程内存管理器Dlg::OnMemoryReadOperation)
	ON_COMMAND(ID_MEMORY_WRITE_OPERATION, &C进程内存管理器Dlg::OnMemoryWriteOperation)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_PROCESS_MEMORY, &C进程内存管理器Dlg::OnNMRClickListProcessMemory)
	ON_COMMAND(ID_PROTECT_NOACCESS, &C进程内存管理器Dlg::OnProtectNoAccess)
	ON_COMMAND(ID_PROTECT_READ, &C进程内存管理器Dlg::OnProtectRead)
	ON_COMMAND(ID_PROTECT_READWRITE, &C进程内存管理器Dlg::OnProtectReadWrite)
	ON_COMMAND(ID_PROTECT_READWRITE_GUARD, &C进程内存管理器Dlg::OnProtectReadWriteGuard)
	ON_COMMAND(ID_PROTECT_READEXECUTE, &C进程内存管理器Dlg::OnProtectReadExecute)
	ON_COMMAND(ID_PROTECT_WRITECOPY, &C进程内存管理器Dlg::OnProtectWriteCopy)
	ON_COMMAND(ID_PROTECT_RECOVER, &C进程内存管理器Dlg::OnProtectRecover)
END_MESSAGE_MAP()


// C进程内存管理器Dlg 消息处理程序

BOOL C进程内存管理器Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	if (m_DeviceHandle==NULL)
	{
		OpenDeviceObject(L"\\\\.\\KAnti911");
	}

	m_CListCtrl_ProcessMemorys.SetExtendedStyle(LVS_EX_FULLROWSELECT);
	m_CListCtrl_ProcessMemorys.InsertColumn(0, _T("内存基地址"), LVCFMT_LEFT, 160);
	m_CListCtrl_ProcessMemorys.InsertColumn(1, _T("范围"), LVCFMT_LEFT, 150);
	m_CListCtrl_ProcessMemorys.InsertColumn(2, _T("保护"), LVCFMT_LEFT, 100);
	m_CListCtrl_ProcessMemorys.InsertColumn(3, _T("状态"), LVCFMT_LEFT, 80);
	m_CListCtrl_ProcessMemorys.InsertColumn(4, _T("类型"), LVCFMT_LEFT, 80);


	InitSolidMenu();
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}
VOID C进程内存管理器Dlg::InitSolidMenu()
{
	HMENU  Menu;
	Menu = LoadMenu(NULL, MAKEINTRESOURCE(IDR_MENU_MAIN));               //载入菜单资源
	::SetMenu(this->GetSafeHwnd(), Menu);                                //为窗口设置菜单
	::DrawMenuBar(this->GetSafeHwnd());                                  //显示菜单
}

void C进程内存管理器Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void C进程内存管理器Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR C进程内存管理器Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}
void C进程内存管理器Dlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateData(TRUE);
	if (m_CEdit_ProcessIdentity == 0)
	{
		MessageBox(L"ID错误");
		return;
	}
	SendIoControlCode(ENUM_PROCESS_MEMORYS);
}

BOOL C进程内存管理器Dlg::SendIoControlCode(ULONG32 IoControlCode)
{
	switch (IoControlCode)
	{
	case ENUM_PROCESS_MEMORYS:
	{
		QueryVirtualMemory();

		if (m_Vectors.empty())
		{
			return FALSE;
		}
		for (vector <MEMORY_INFORMATION>::iterator i = m_Vectors.begin();
			i != m_Vectors.end();
			i++)
		{
			AddItemToControlList(*i);
		}

		break;
	}
	default:
		break;
	}
	return TRUE;
}
BOOL C进程内存管理器Dlg::QueryVirtualMemory()
{
	BOOL  IsOk = FALSE;
	DWORD ReturnLength = 0;
	m_Vectors.clear();
	m_CListCtrl_ProcessMemorys.DeleteAllItems();
	ULONG32 NumberOfMemory = 0x10;
	PMEMORYS_INFORMATION MemorysInfo = NULL;


	COMMUNICATE_PROCESS_MEMORY v1;

	v1.OperateType = ENUM_PROCESS_MEMORYS;
	v1.u1.Query.ProcessIdentity = m_CEdit_ProcessIdentity;
	do
	{
		ULONG32 BufferLength = 0;
		if (MemorysInfo)
		{
			free(MemorysInfo);
			MemorysInfo = NULL;
		}
	    BufferLength = sizeof(MEMORYS_INFORMATION) + NumberOfMemory * sizeof(MEMORY_INFORMATION);
		MemorysInfo = (PMEMORYS_INFORMATION)malloc(BufferLength);
		if (!MemorysInfo)
		{
			break;
		}
		memset(MemorysInfo, 0, BufferLength);
		IsOk = DeviceIoControl(m_DeviceHandle, MY_CTL_CODE,
			&v1,
			sizeof(COMMUNICATE_PROCESS_MEMORY),
			MemorysInfo,
			BufferLength,
			&ReturnLength,
			NULL);
		NumberOfMemory = MemorysInfo->NumberOfMemory + 10;
	} while (IsOk == FALSE && GetLastError() == ERROR_INSUFFICIENT_BUFFER);
	if (IsOk && MemorysInfo)
	{
		for (ULONG i = 0; i < MemorysInfo->NumberOfMemory; i++)
		{
			m_Vectors.push_back(MemorysInfo->MemoryInfo[i]);
		}
		IsOk = TRUE;
	}
	if (MemorysInfo)
	{
		free(MemorysInfo);
		MemorysInfo = NULL;
	}
	return IsOk;
}
VOID C进程内存管理器Dlg::AddItemToControlList(MEMORY_INFORMATION MemorysInfo)
{
	CString BaseAddress,RegionSize,Protect, State, Type;
	BaseAddress.Format(_T("0x%04p"), MemorysInfo.BaseAddress);
	RegionSize.Format(_T("0x%08p"), MemorysInfo.RegionSize);
	Protect.Format(_T("%d"), MemorysInfo.Protect);
	State.Format(_T("%p"), MemorysInfo.State);
	Type.Format(_T("%p"), MemorysInfo.Type);
	switch (MemorysInfo.Type)
	{
	case 0x1000000:
	{
		Type = _T("Image");
		break;
	}
	case 0x40000:
	{
		Type = _T("Map");
		break;
	}
	case 0x20000:
	{

		Type = _T("Private");
		break;
	}
	default:
	{
		Type = _T("");
		break;
	}
	}
	switch (MemorysInfo.State)
	{
	case 0x10000:
	{

		State = _T("Free");
		break;
	}
	case 0x2000:
	{
		State = _T("Reserve");
		break;
	}
	case 0x1000:
	{
		State = _T("Commit");
		break;
	}
	default:
	{
		State = _T("");
		break;
	}
	}
	switch (MemorysInfo.Protect)
	{
	case 1:
	{
		Protect = _T("No Access");
		break;
	}
	case 2:
	{
		Protect = _T("Read");
		break;
	}
	case 4:
	{
		Protect = _T("ReadWrite");
		break;
	}
	case 260:
	{
		Protect = _T("ReadWriteGuard");
		break;
	}
	case 32:
	{
		Protect = _T("ReadExecute");
		break;
	}
	case 8:
	{
		Protect = _T("WriteCopy");
		break;
	}

	default:
	{
		Protect = _T("");
		break;
	}
	}
	int n = m_CListCtrl_ProcessMemorys.InsertItem(m_CListCtrl_ProcessMemorys.GetItemCount(),BaseAddress);
	m_CListCtrl_ProcessMemorys.SetItemText(n, 1, RegionSize);
	m_CListCtrl_ProcessMemorys.SetItemText(n, 2, Protect);
	m_CListCtrl_ProcessMemorys.SetItemText(n, 3, State);
	m_CListCtrl_ProcessMemorys.SetItemText(n, 4, Type);
}

void C进程内存管理器Dlg::OnMemoryReadOperation()
{
	// TODO: 在此添加命令处理程序代码

	UpdateData(TRUE);
	if (m_CEdit_ProcessIdentity == 0)
	{
		return;
	}
	CReadOperationDlg Dlg(m_CEdit_ProcessIdentity,this);
	Dlg.DoModal();


}


void C进程内存管理器Dlg::OnMemoryWriteOperation()
{
	// TODO: 在此添加命令处理程序代码

	UpdateData(TRUE);
	if (m_CEdit_ProcessIdentity == 0)
	{
		return;
	}
	CWriteOperationDlg Dlg(m_CEdit_ProcessIdentity, this);
	Dlg.DoModal();
}

void C进程内存管理器Dlg::OnNMRClickListProcessMemory(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码


	CMenu	Menu;
	Menu.LoadMenu(IDR_MENU_MAIN);
	CMenu*	SubMenu = Menu.GetSubMenu(0);
	CPoint	Point;
	GetCursorPos(&Point);
	
	if (m_CListCtrl_ProcessMemorys.GetSelectedCount()!= 0)
	{

		// [FIX] SubMenu->DeleteMenu(0, MF_BYPOSITION);  // keep Read/Write items in the context menu
		// [FIX] SubMenu->DeleteMenu(0, MF_BYPOSITION);  // keep Read/Write items in the context menu


		POSITION Position = m_CListCtrl_ProcessMemorys.GetFirstSelectedItemPosition();
		int Item = m_CListCtrl_ProcessMemorys.GetNextSelectedItem(Position);
			
		m_OldProtect = m_CListCtrl_ProcessMemorys.GetItemData(Item);

		if (m_OldProtect==0)
		{
			// [FIX] SubMenu->DeleteMenu(1, MF_BYPOSITION);  // keep full menu; was deleting an item on NoAccess pages

		}

		SubMenu->TrackPopupMenu(TPM_LEFTALIGN, Point.x, Point.y, this);




		CString  v5;
		CString  v7;
		
		if (Item == -1)
		{
			return;
		}
		v5 = m_CListCtrl_ProcessMemorys.GetItemText(Item, 0);
		_stscanf(v5.GetBuffer() + 2, _T("%p"), &m_BaseAddress);
		v7 = m_CListCtrl_ProcessMemorys.GetItemText(Item, 1);
		_stscanf(v7.GetBuffer() + 2, _T("%p"), &m_RegionSize);




	}
	*pResult = 0;
}


void C进程内存管理器Dlg::OnProtectNoAccess()
{
	// TODO: 在此添加命令处理程序代码




	if (m_CEdit_ProcessIdentity == 0)
	{
		return;
	}


	m_NewProtect = 1;	
	if (VirtualProtect()==TRUE)
	{
		POSITION Position = m_CListCtrl_ProcessMemorys.GetFirstSelectedItemPosition();
		int Item = m_CListCtrl_ProcessMemorys.GetNextSelectedItem(Position);
		if (Item == -1)
		{
			return;
		}


		CString Protect;
		Protect = _T("No Access");

		m_CListCtrl_ProcessMemorys.SetItemText(Item, 2, Protect);

		if (m_OldProtect)
		{
			m_CListCtrl_ProcessMemorys.SetItemData(Item, (DWORD)m_OldProtect);
		}
	
	}
}


void C进程内存管理器Dlg::OnProtectRead()
{
	// TODO: 在此添加命令处理程序代码

	if (m_CEdit_ProcessIdentity == 0)
	{
		return;
	}


	m_NewProtect = 2;
	if (VirtualProtect() == TRUE)
	{
		POSITION Position = m_CListCtrl_ProcessMemorys.GetFirstSelectedItemPosition();
		int Item = m_CListCtrl_ProcessMemorys.GetNextSelectedItem(Position);
		if (Item == -1)
		{
			return;
		}
	
		CString Protect;
		Protect =  _T("Read");

		m_CListCtrl_ProcessMemorys.SetItemText(Item, 2, Protect);

		if (m_OldProtect)
		{
			m_CListCtrl_ProcessMemorys.SetItemData(Item, (DWORD)m_OldProtect);
		}

		if (m_OldProtect)
		{
			m_CListCtrl_ProcessMemorys.SetItemData(Item, (DWORD)m_OldProtect);
		}

	}

}


void C进程内存管理器Dlg::OnProtectReadWrite()
{
	// TODO: 在此添加命令处理程序代码
	if (m_CEdit_ProcessIdentity == 0)
	{
		return;
	}


	m_NewProtect = 4;
	if (VirtualProtect() == TRUE)
	{
		POSITION Position = m_CListCtrl_ProcessMemorys.GetFirstSelectedItemPosition();
		int Item = m_CListCtrl_ProcessMemorys.GetNextSelectedItem(Position);
		if (Item == -1)
		{
			return;
		}
		CString Protect;
		Protect = _T("ReadWrite");

		m_CListCtrl_ProcessMemorys.SetItemText(Item, 2, Protect);

		if (m_OldProtect)
		{
			m_CListCtrl_ProcessMemorys.SetItemData(Item, (DWORD)m_OldProtect);
		}

		if (m_OldProtect)
		{
			m_CListCtrl_ProcessMemorys.SetItemData(Item, (DWORD)m_OldProtect);
		}

	}
}


void C进程内存管理器Dlg::OnProtectReadWriteGuard()
{
	// TODO: 在此添加命令处理程序代码

	if (m_CEdit_ProcessIdentity == 0)
	{
		return;
	}

	m_NewProtect = 260;
	if (VirtualProtect() == TRUE)
	{
		POSITION Position = m_CListCtrl_ProcessMemorys.GetFirstSelectedItemPosition();
		int Item = m_CListCtrl_ProcessMemorys.GetNextSelectedItem(Position);
		if (Item == -1)
		{
			return;
		}
		CString Protect;
		Protect = _T("ReadWriteGuard");

		m_CListCtrl_ProcessMemorys.SetItemText(Item, 2, Protect);

		if (m_OldProtect)
		{
			m_CListCtrl_ProcessMemorys.SetItemData(Item,(DWORD)m_OldProtect);
		}
		

	}
}


void C进程内存管理器Dlg::OnProtectReadExecute()
{
	// TODO: 在此添加命令处理程序代码
	if (m_CEdit_ProcessIdentity== 0)
	{
		return;
	}

	m_NewProtect = 32;
	if (VirtualProtect() == TRUE)
	{
		POSITION Position = m_CListCtrl_ProcessMemorys.GetFirstSelectedItemPosition();
		int Item = m_CListCtrl_ProcessMemorys.GetNextSelectedItem(Position);
		if (Item == -1)
		{
			return;
		}
		CString Protect;
		Protect = _T("ReadExecute");

		m_CListCtrl_ProcessMemorys.SetItemText(Item, 2, Protect);

		if (m_OldProtect)
		{
			m_CListCtrl_ProcessMemorys.SetItemData(Item, (DWORD)m_OldProtect);
		}

		if (m_OldProtect)
		{
			m_CListCtrl_ProcessMemorys.SetItemData(Item, (DWORD)m_OldProtect);
		}

	}
}


void C进程内存管理器Dlg::OnProtectWriteCopy()
{
	// TODO: 在此添加命令处理程序代码
	if (m_CEdit_ProcessIdentity == 0)
	{
		return;
	}


	m_NewProtect = 8;

	if (VirtualProtect() == TRUE)
	{
		POSITION Position = m_CListCtrl_ProcessMemorys.GetFirstSelectedItemPosition();
		int Item = m_CListCtrl_ProcessMemorys.GetNextSelectedItem(Position);
		if (Item == -1)
		{
			return;
		}
		CString Protect;
		Protect = _T("WriteCopy");

		m_CListCtrl_ProcessMemorys.SetItemText(Item, 2, Protect);

		if (m_OldProtect)
		{
			m_CListCtrl_ProcessMemorys.SetItemData(Item, (DWORD)m_OldProtect);
		}
		if (m_OldProtect)
		{
			m_CListCtrl_ProcessMemorys.SetItemData(Item, (DWORD)m_OldProtect);
		}

	}
}

BOOL C进程内存管理器Dlg::VirtualProtect()
{

	
	BOOL  IsOk = FALSE;
	
	DWORD ReturnLength = 0;
	BOOL  IsReturn = FALSE;

	COMMUNICATE_PROCESS_MEMORY v5;
	memset(&v5, 0, sizeof(COMMUNICATE_PROCESS_MEMORY));
	v5.OperateType = MODIFY_PROCESS_MEMORYS;
	v5.u1.Modify.ProcessIdentity = m_CEdit_ProcessIdentity;
	v5.u1.Modify.BaseAddress = m_BaseAddress;
	v5.u1.Modify.NewProtect = m_NewProtect;
	v5.u1.Modify.RegionSize = m_RegionSize;


	IsOk = DeviceIoControl(m_DeviceHandle, MY_CTL_CODE,
		&v5,
		sizeof(COMMUNICATE_PROCESS_MEMORY),
		&v5.u1.Modify.OldProtect,
		sizeof(ULONG),
		&ReturnLength,
		NULL);


	m_OldProtect = v5.u1.Modify.OldProtect;
	return IsOk;
}

void C进程内存管理器Dlg::OnProtectRecover()
{
	// TODO: 在此添加命令处理程序代码


	BOOL  IsOk = FALSE;
	DWORD ReturnLength = 0;
	BOOL  IsReturn = FALSE;

	POSITION Position = m_CListCtrl_ProcessMemorys.GetFirstSelectedItemPosition();
	int Item = m_CListCtrl_ProcessMemorys.GetNextSelectedItem(Position);

	m_OldProtect = m_CListCtrl_ProcessMemorys.GetItemData(Item);

	if (m_OldProtect==0)
	{
		return;
	}

	CString  v6;
	CString  v7;

	if (Item == -1)
	{
		return;
	}
	v6 = m_CListCtrl_ProcessMemorys.GetItemText(Item, 0);
	_stscanf(v6.GetBuffer() + 2, _T("%p"), &m_BaseAddress);
	v7 = m_CListCtrl_ProcessMemorys.GetItemText(Item, 1);
	_stscanf(v7.GetBuffer() + 2, _T("%p"), &m_RegionSize);



	COMMUNICATE_PROCESS_MEMORY v5;
	memset(&v5, 0, sizeof(COMMUNICATE_PROCESS_MEMORY));

	v5.OperateType = MODIFY_PROCESS_MEMORYS;
	v5.u1.Modify.ProcessIdentity = m_CEdit_ProcessIdentity;
	v5.u1.Modify.BaseAddress = m_BaseAddress;
	v5.u1.Modify.NewProtect = m_OldProtect;
	v5.u1.Modify.RegionSize = m_RegionSize;



	IsOk = DeviceIoControl(m_DeviceHandle, MY_CTL_CODE,
		&v5,
		sizeof(COMMUNICATE_PROCESS_MEMORY),
		&v5.u1.Modify.OldProtect,
		sizeof(ULONG),
		&ReturnLength,
		NULL);

	CString Protect;
	if (IsOk==TRUE)
	{
		switch (m_OldProtect)
		{
		case 1:
		{
			Protect = _T("No Access");
			break;
		}
		case 2:
		{
			Protect = _T("Read");
			break;
		}
		case 4:
		{
			Protect = _T("ReadWrite");
			break;
		}
		case 260:
		{
			Protect = _T("ReadWriteGuard");
			break;
		}
		case 32:
		{
			Protect = _T("ReadExecute");
			break;
		}
		case 8:
		{
			Protect = _T("WriteCopy");
			break;
		}

		default:
		{
			Protect = _T("");
			break;
		}
		}

		m_CListCtrl_ProcessMemorys.SetItemText(Item, 2, Protect);
		m_CListCtrl_ProcessMemorys.SetItemData(Item, 0);
		
	}




}
