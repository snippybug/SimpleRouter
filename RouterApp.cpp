#include "RouterApp.h"
#include "CDlgRouter.h"

CRouterApp app;
CDlgRouter *prouter;

BOOL CRouterApp::InitInstance(){
	CDlgRouter dlg;
	m_pMainWnd = &dlg;
	prouter = &dlg;
	dlg.DoModal();
	return FALSE;
}