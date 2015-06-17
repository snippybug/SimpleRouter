#include <afxwin.h>
#include <afxcmn.h>
#include <pcap.h>
#include "net.h"

#define LocalIP1 (((sockaddr_in *)devaddr1->addr)->sin_addr.S_un.S_addr)
#define LocalIP2 (((sockaddr_in *)devaddr2->addr)->sin_addr.S_un.S_addr)

class CDlgRouter : public CDialog
{
public:
	CDlgRouter(CWnd *parent = NULL);
protected:
	virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange *pDX);
	afx_msg void addRoute();
	afx_msg void removeRoute();
	afx_msg void OnClose();
	afx_msg LRESULT route(WPARAM, LPARAM);
	DECLARE_MESSAGE_MAP()
private:

	CListBox m_loglist;
	CListBox m_routelist;
	CIPAddressCtrl m_submask;
	CIPAddressCtrl m_dstip;
	CIPAddressCtrl m_nexthop;
};