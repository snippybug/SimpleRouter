#include <pcap.h>
#include <Windows.h>
#include <WinSock2.h>
#include <CommCtrl.h>
#include <process.h>
#include "resource.h"

#pragma pack(1)

typedef struct FrameHeader_t{	// frame首部
	BYTE DescMAC[6];
	BYTE SrcMAC[6];
	WORD FrameType;
}FrameHeader_t;

typedef struct ARPFrame_t{
	FrameHeader_t	FrameHeader;
	WORD			HardwareType;	// 硬件类型
	WORD			ProtocolType;	// 协议类型
	BYTE			HLen;			// 硬件地址长度
	BYTE			PLen;			// 协议地址长度
	WORD			Operation;		// 操作
	BYTE			SendHa[6];		// 源MAC地址
	DWORD			SendIP;			// 源IP地址
	BYTE			RecvHa[6];		// 目的MAC地址
	DWORD			RecvIP;			// 目的IP
}ARPFrame_t;

typedef struct IPHeader_t{	// IPv4首部
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;		
	WORD ID;
	WORD FFlag_Segment;
	BYTE TTL;
	BYTE Protocol;
	WORD CheckSum;
	ULONG SrcIP;
	ULONG DstIP;
}IPHeader_t;

typedef struct IPFrame_t{
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}IPFrame_t;

#pragma pack()

typedef struct Param{
	HANDLE hEvent;
	PVOID data;
}Param, *PParam;

struct IPEntry{
	DWORD submask;
	DWORD dstip;
	DWORD nexthop;
	struct IPEntry *next;
}*routeTable;		// 路由表, 所有数据均为网络序

struct ARPEntry{
	DWORD ip;
	BYTE mac[6];
	struct ARPEntry *next;
}*arpTable;

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
TCHAR* CharToTchar(CHAR *_char);
VOID winprintf(CHAR * fmt, ...);
VOID addRoute(HWND);
VOID removeRoute(HWND);
VOID thread_capture(PVOID);
VOID thread_arp(PVOID);
VOID route(HWND, PVOID);

CHAR errbuf[PCAP_ERRBUF_SIZE];	// 错误信息缓冲区
pcap_if_t *alldevs;		// 指向设备链表的指针
pcap_if_t *dev;
pcap_t *adhandle;
pcap_addr *devaddr1, *devaddr2;
BYTE LocalMAC[6];
CRITICAL_SECTION cs;		// arp表的临界区

INT initNet();
VOID clearNet();
VOID GetMAC(DWORD, BYTE[6], int);
#define LocalIP1 (((sockaddr_in *)devaddr1->addr)->sin_addr.S_un.S_addr)
#define LocalIP2 (((sockaddr_in *)devaddr2->addr)->sin_addr.S_un.S_addr)

#define DEBUG
#define TEST
//#define SINGLE
#define WM_ROUTE WM_USER

void alloc_or_attach();
void freeCon();

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
	PSTR szCmdLine, int iCmdShow)
{
	static TCHAR szAppName[] = TEXT("SimpleRoute");
	HWND	hwnd;
	MSG		msg;
	WNDCLASS	wndclass;

	wndclass.style = CS_HREDRAW | CS_VREDRAW;
	wndclass.lpfnWndProc = WndProc;
	wndclass.cbClsExtra = 0;
	wndclass.cbWndExtra = DLGWINDOWEXTRA;
	wndclass.hInstance = hInstance;
	wndclass.hIcon = LoadIcon(hInstance, szAppName);
	wndclass.hCursor = LoadCursor(NULL, IDC_ARROW);
	wndclass.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
	wndclass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wndclass.lpszMenuName = NULL;
	wndclass.lpszClassName = szAppName;

	if (!RegisterClass(&wndclass)){
		MessageBox(NULL, TEXT("This program requires Windows NT"),
			szAppName, MB_ICONERROR);
		return 0;
	}

	hwnd = CreateDialog(hInstance, szAppName, 0, NULL);

	ShowWindow(hwnd, iCmdShow);

	while (GetMessage(&msg, NULL, 0, 0)){
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam){
	HWND hwnd1;
	TCHAR szbuf[100];
	switch (message){
	case WM_CREATE:
#ifdef DEBUG
		alloc_or_attach();
#endif;
		if (initNet() < 0){	// 获取网卡信息，选择网卡，获取MAC地址与IP地址信息
			SendMessage(hwnd, WM_CLOSE, 0, 0);
			return 0;
		}
		InitializeCriticalSection(&cs);
		_beginthread(thread_capture, 0, hwnd);	// 创建路由进程
		break;
	case WM_COMMAND:
		switch (LOWORD(wParam)){
		case IDC_RETURN:
			PostMessage(hwnd, WM_CLOSE, 0, 0);
			return 0;
		case IDC_DEBUG:
			hwnd1 = GetDlgItem(hwnd, IDC_LOG);
			SendMessage(hwnd1, LB_ADDSTRING, 0, (LPARAM)CharToTchar(dev->description));
			wsprintf(szbuf, TEXT("MAC: %02X:%02X:%02X:%02X:%02X:%02X"), LocalMAC[0], LocalMAC[1], LocalMAC[2], LocalMAC[3], LocalMAC[4], LocalMAC[5]);
			SendMessage(hwnd1, LB_ADDSTRING, 0, (LPARAM)szbuf);
			wsprintf(szbuf, TEXT("IP addr1: %s"), CharToTchar(inet_ntoa(((sockaddr_in *)devaddr1->addr)->sin_addr)));
			SendMessage(hwnd1, LB_ADDSTRING, 0, (LPARAM)szbuf);
			wsprintf(szbuf, TEXT("IP addr2: %s"), CharToTchar(inet_ntoa(((sockaddr_in *)devaddr2->addr)->sin_addr)));
			SendMessage(hwnd1, LB_ADDSTRING, 0, (LPARAM)szbuf);
			SendMessage((HWND)lParam, WM_CLOSE, 0, 0);
			return 0;
		case IDC_ADDROUTE:
			addRoute(hwnd);
			return 0;
		case IDC_REMOVEROUTE:
			removeRoute(hwnd);
			return 0;
		};
		break;
	case WM_ROUTE:
		route(hwnd, (PVOID)lParam);
		return 0;
	case WM_CLOSE:
		clearNet();
#ifdef DEBUG
		freeCon();
#endif
		DeleteCriticalSection(&cs);
		DestroyWindow(hwnd);
		return 0;
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	};
	return DefWindowProc(hwnd, message, wParam, lParam);
}

// ASCII字符转宽字符
TCHAR* CharToTchar(CHAR *_char){
	static TCHAR tchar[500];
	MultiByteToWideChar(CP_ACP, 0, _char, strlen(_char) + 1, tchar, 500);
	return tchar;
}

VOID winprintf(char * fmt, ...){
#define BUFSIZE 256
	va_list ap;
	TCHAR wbuf[BUFSIZE] = { 0 };
	TCHAR wfmt[BUFSIZE] = { 0 };
	MultiByteToWideChar(CP_ACP, 0, fmt, BUFSIZE, wfmt, BUFSIZE);
	va_start(ap, fmt);
	wvsprintf(wbuf, wfmt, ap);
	va_end(ap);
	MessageBox(NULL, wbuf, TEXT("Debug"), MB_OK);
}

INT initNet(){
	// 获取本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		winprintf(errbuf);
		return -1;
	}

	// 选择接口和IP地址
#ifdef TEST
	dev = alldevs;
#else
	dev = alldevs->next;
#endif
#ifdef DEBUG
	printf("desc=%s\n", dev->description);
#endif
	pcap_addr *paddr = dev->addresses;
	while (paddr){
		if (paddr->addr->sa_family == AF_INET)
			break;
		paddr = paddr->next;
	}
	if (!paddr){
		winprintf("No IPv4 address");
		return -2;
	}
	else{
		devaddr1 = paddr;
#ifdef SINGLE
		devaddr2 = devaddr1;
#else
		devaddr2 = paddr->next;
#endif
	}

	// 打开设备
	if ((adhandle = pcap_open(dev->name, 65536, 0, 10, NULL, errbuf)) == NULL){
		winprintf(errbuf);
		return -3;
	}
	GetMAC(LocalIP1, LocalMAC, 1);
	return 0;
}

VOID clearNet(){
	if (adhandle)
		pcap_close(adhandle);
	if (alldevs)
		pcap_freealldevs(alldevs);
	if (routeTable){
		struct IPEntry *temp = routeTable;
		while (temp){
			routeTable = routeTable->next;
			free(temp);
			temp = routeTable;
		}
	}
}

// own为1, 代表获取本机MAC地址
VOID GetMAC(DWORD ip, BYTE mac[6], int own){
	ARPFrame_t	ARPFrame;
	int i;

	// 设置ARP包的以太帧部分
	ARPFrame.FrameHeader.FrameType = htons(0x0806);		// frame类型是ARP
	for (i = 0; i<6; i++){
		ARPFrame.FrameHeader.SrcMAC[i] = (own ? 0x66 : LocalMAC[i]);		// 如果获取本机MAC地址，设置伪地址66-66-66-66-66-66
		ARPFrame.FrameHeader.DescMAC[i] = 0xff;			// 以太网广播地址
	}

	// 设置ARP包的ARP帧部分
	ARPFrame.HardwareType = htons(0x0001);				// 硬件类型是以太网
	ARPFrame.ProtocolType = htons(0x0800);				// 协议类型是IPv4
	ARPFrame.HLen = 6;									// 以太网的硬件地址长度为6
	ARPFrame.PLen = 4;									// IPv4的地址长度是4
	ARPFrame.Operation = htons(0x0001);					// 操作是ARP请求
	for (i = 0; i < 6; i++){
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i];
		ARPFrame.RecvHa[i] = 0;
	}
	ARPFrame.SendIP = (own ? htonl(0x0a0a0114) : LocalIP1);	// 如果获取本机MAC地址，设置伪IP：10.10.1.20
	ARPFrame.RecvIP = ip;

	// 发送ARP包
	if (pcap_sendpacket(adhandle, (u_char *)&ARPFrame, sizeof(ARPFrame)) != 0){
		winprintf("Can't Send ARP packet");
		return;
	}

	int bfind = 0;
	if(own){		// 当获取本机MAC地址时，抓包线程还未启动，只能自己抓
		struct pcap_pkthdr *header;
		const u_char *pkt_data;
		ARPFrame_t *parp;
		int res;

		bfind = 1;
		while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){
			if (res == 0){
				continue;
			}
			parp = (ARPFrame_t *)pkt_data;
#ifdef DEBUG
			printf("ARP packet: from %x to %x\n", parp->SendIP, parp->RecvIP);
#endif
			if (parp->FrameHeader.FrameType == htons(0x0806)		// 如果接受到ARP包
				&& parp->SendIP == ARPFrame.RecvIP)					// 并且发送方是目的IP
				break;
		}
		if (res < 0){
			winprintf("Error in receiving packet");
			return;
		}
		else if(bfind){
			for (i = 0; i < 6; i++)
				mac[i] = parp->SendHa[i];
		}
	}
	else{
		for (i = 0; i < 10; i++){
			EnterCriticalSection(&cs);
			struct ARPEntry *temp = arpTable;
			while (temp){
				if (temp->ip == ip){
					bfind = 1;
					int j;
					for (j = 0; j < 6; j++){
						mac[j] = temp->mac[j];		// Notice!! 把j写成i，浪费不少时间
					}
					break;
				}
				temp = temp->next;
			}
			LeaveCriticalSection(&cs);
			if (bfind){
				break;
			}
			Sleep(200);
		}
	}
	struct in_addr taddr;
	taddr.S_un.S_addr = ip;
#ifdef DEBUG
	if (bfind == 0){
		printf("Warning: can't get MAC address for %s, maybe time out\n", inet_ntoa(taddr));
	}
	else{
		printf("GetMAC: %s=%02X:%02X:%02X:%02X:%02X:%02X\n", inet_ntoa(taddr), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6]);
	}
#endif
}

VOID addRoute(HWND hwnd){
	HWND htable = GetDlgItem(hwnd, IDC_ROUTETABLE);
	DWORD submask, dstip, nexthop;
	HWND htemp;
	struct IPEntry *routry = NULL;
	htemp = GetDlgItem(hwnd, IDC_SUBMASK);
	SendMessage(htemp, IPM_GETADDRESS, 0, (LPARAM)&submask);		// 获取子网掩码
	htemp = GetDlgItem(hwnd, IDC_DSTIP);
	SendMessage(htemp, IPM_GETADDRESS, 0, (LPARAM)&dstip);	// 目的地址
	htemp = GetDlgItem(hwnd, IDC_NEXTHOP);
	SendMessage(htemp, IPM_GETADDRESS, 0, (LPARAM)&nexthop);
	
	// 添加到内部路由表
	routry = (struct IPEntry*)malloc(sizeof(struct IPEntry));
	if (routry == NULL){
		winprintf("Out of memory");
		SendMessage(hwnd, WM_CLOSE, 0, 0);
		return;
	}
	routry->submask = htonl(submask);
	routry->dstip = htonl(dstip);
	routry->nexthop = htonl(nexthop);
	routry->next = routeTable;
	routeTable = routry;

	// 更新显示
	TCHAR szbuf[50];
	CHAR buf[50];
	struct in_addr taddr;
	taddr.S_un.S_addr = routry->submask;
	sprintf(buf, "%s", inet_ntoa(taddr));
	taddr.S_un.S_addr = routry->dstip;
	sprintf(buf, "%s -- %s", buf, inet_ntoa(taddr));
	taddr.S_un.S_addr = routry->nexthop;
	sprintf(buf, "%s -- %s", buf, inet_ntoa(taddr));
	wsprintf(szbuf, TEXT("%s %s"), CharToTchar(buf), nexthop ? 0 : TEXT("(直接投递)"));
	SendMessage(htable, LB_ADDSTRING, 0, (LPARAM)szbuf);
}

VOID removeRoute(HWND hwnd){
	HWND hTable = GetDlgItem(hwnd, IDC_ROUTETABLE);
	int i;
	// 获取当前选项
	if ((i = SendMessage(hTable, LB_GETCURSEL, 0, 0)) == LB_ERR){		// 当前没有选中任何选项
		return;
	}

	// 删除外部显示
	int n=SendMessage(hTable, LB_DELETESTRING, i, 0);	// n是剩下的项的个数

	struct IPEntry *temp = routeTable;
	if (i == 0){
		routeTable = routeTable->next;
	}
	else{
		int j = 0;
		struct IPEntry *before = temp;
		i = n + 1 - i;			// 倒数第i个
		while (j < (i - 1)){
			before = before->next;
			j++;
		}
		temp = before->next;
		before->next = temp->next;
	}
	free(temp);
}

// 负责抓包
VOID thread_capture(PVOID pvoid){
	HWND hwin = (HWND)pvoid;
	DWORD netmask;
	struct bpf_program fcode;

	HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);		// 用于通知arp线程有数据包处理
	Param param;
	param.hEvent = hEvent;
	param.data = NULL;
	// 启动arp线程处理arp包
	_beginthread(thread_arp, 0, &param);

	if (dev->addresses != NULL){
		netmask = ((struct sockaddr_in *)dev->addresses->netmask)->sin_addr.S_un.S_addr;
	}
	else{
		netmask = 0xffffff;
	}
	// 设置过滤器：IPv4，目的IP不是自己，目的MAC是自己或者ARP
	char filter[150];
	sprintf(filter, "(ip and not dst host %s", inet_ntoa(((struct sockaddr_in*)devaddr1->addr)->sin_addr));
	sprintf(filter, "%s and not dst host %s", filter, inet_ntoa(((struct sockaddr_in*)devaddr2->addr)->sin_addr));
	sprintf(filter, "%s and ether dst %02X:%02X:%02X:%02X:%02X:%02X)", filter, LocalMAC[0], LocalMAC[1], LocalMAC[2], LocalMAC[3], LocalMAC[4], LocalMAC[5]);
	sprintf(filter, "%s or (arp and (dst host %s", filter, inet_ntoa(((struct sockaddr_in*)devaddr1->addr)->sin_addr));
	sprintf(filter, "%s or dst host %s))", filter, inet_ntoa(((struct sockaddr_in*)devaddr2->addr)->sin_addr));
	if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0){
		winprintf("Unable to compile the packet filter. Check the Syntax");
		goto end;
	}
	if (pcap_setfilter(adhandle, &fcode) < 0){
		winprintf("Error setting the filter");
		goto end;
	}

	// 开始抓包
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){
		if (res == 0)
			continue;
		if (((FrameHeader_t*)pkt_data)->FrameType == htons(0x0806)){		// 如果是ARP包
#ifdef DEBUG
			printf("Time when receiving an ARP packet: %dms\n", clock());
#endif
			ARPFrame_t *header = (ARPFrame_t*)pkt_data;
			int n = sizeof(ARPFrame_t);
			if (param.data){		// 表示上一个ARP包还没处理结束
#ifdef DEBUG
				printf("Warning: ARP packet is dropped because the last one hasn't been handled\n");
#endif
				continue;
			}
			param.data = malloc(n);
			memcpy(param.data, header, n);
			SetEvent(hEvent);			// 通知arp线程
		}
		else{																// 否则是用于路由的IPv4的包
#ifdef DEBUG
			printf("Time when receiving an IP packet: %dms\n", clock());
#endif
			IPFrame_t *header = (IPFrame_t *)pkt_data;
			int n = ntohs(header->IPHeader.TotalLen) + sizeof(header->FrameHeader);
			PVOID data = malloc(n);
			memcpy(data, header, n);		// 将数据包完整拷贝，然后通知主进程
			PostMessage(hwin, WM_ROUTE, 0, (LPARAM)data);
#ifdef DEBUG
			struct in_addr taddr;
			taddr.S_un.S_addr = header->IPHeader.SrcIP;
			printf("thread_capture: IP packet, from %s", inet_ntoa(taddr));
			taddr.S_un.S_addr = header->IPHeader.DstIP;
			printf(" to %s, n=%d\n", inet_ntoa(taddr), n);
#endif
		}
	}
	if (res == -1){
		winprintf("Error reading the packets: %s", pcap_geterr(adhandle));
		goto end;
	}

end:
	_endthread();
}

#ifdef DEBUG
void alloc_or_attach() {
	if (!AllocConsole()) {
		AttachConsole(GetCurrentProcessId());
	}
	freopen("CONOUT$", "w", stdout); // redirect cout to hConsole
	freopen("CONIN$", "r", stdin); // redirect cout to hConsole
}

void freeCon() {
	FreeConsole();
}
#endif

VOID route(HWND hwnd, PVOID data){
	IPFrame_t *packet = (IPFrame_t *)data;
	DWORD dstip = packet->IPHeader.DstIP;
	// 由于Wpcap的过滤器，dstip一定不是本机IP
	// 遍历路由表
	struct IPEntry *temp = routeTable;
	struct IPEntry *entry = NULL;
	if (packet->FrameHeader.FrameType == htons(0x0806))		// ARP包直接扔掉
		return;
	while (temp){
		if ((temp->submask & dstip) == temp->dstip){
			if (entry){		// 如果之前已经有匹配项，需要比较掩码位数
				if (temp->submask > entry->submask)
					entry = temp;
			}
			else{
				entry = temp;
			}
		}
		temp = temp->next;
	}
	if (entry == NULL){		// 没有匹配项就抛弃数据包
#ifdef DEBUG
		printf("Packet is dropped without route entry matched\n");
#endif
		goto out;
	}
#ifdef DEBUG
	printf("Time when ready to forward the packet: %dms\n", clock());
	printf("Packet is forwarded: dstip=%x, submask=%x, nexthop=%x\n", entry->dstip, entry->submask, entry->nexthop);
#endif
	// 否则，准备转发
	BYTE nextMAC[6];
	if (entry->nexthop){		// 获取下一跳步的MAC地址
		GetMAC(entry->nexthop, nextMAC, 0);
	}
	else{						// 为0代表直接转发
		GetMAC(packet->IPHeader.DstIP, nextMAC, 0);
	}
	int i;
	for (i = 0; i < 6; i++){				// 设置以太网头部
		packet->FrameHeader.DescMAC[i] = nextMAC[i];
		packet->FrameHeader.SrcMAC[i] = LocalMAC[i];
	}
#ifdef DEBUG
	printf("Time when ready to send the packet: %dms\n", clock());
#endif
	if (pcap_sendpacket(adhandle, (u_char *)packet, ntohs(packet->IPHeader.TotalLen) + sizeof(packet->FrameHeader)) < 0){		// 转发
		winprintf("route: %s\n", pcap_geterr(adhandle));
		goto out;
	}
	// 更新记录
	static int count = 0;
	HWND hlog = GetDlgItem(hwnd, IDC_LOG);
	TCHAR buf[100];
	struct in_addr taddr;
	wsprintf(buf, TEXT("Packet %d:"), ++count);
	taddr.S_un.S_addr = packet->IPHeader.SrcIP;
	wsprintf(buf, TEXT("%s From %s"), buf, CharToTchar(inet_ntoa(taddr)));
	taddr.S_un.S_addr = dstip;
	wsprintf(buf, TEXT("%s to %s"), buf, CharToTchar(inet_ntoa(taddr)));
	taddr.S_un.S_addr = entry->nexthop;
	wsprintf(buf, TEXT("%s, nextHop=%s"), buf, CharToTchar(inet_ntoa(taddr)));
	SendMessage(hlog, LB_ADDSTRING, 0, (LPARAM)buf);
out:
	free(data);
	return;
}

VOID thread_arp(PVOID pvoid){
	PParam pparam = (PParam)pvoid;
	while (1){
		WaitForSingleObject(pparam->hEvent, INFINITE);	// 等待thread_route的通知
		ARPFrame_t *packet = (ARPFrame_t *)pparam->data;
		int i;
		struct ARPEntry *entry=(struct ARPEntry*)malloc(sizeof(ARPEntry));
		if (packet->Operation == htons(0x0001) 			// ARP请求
			|| (packet->Operation == htons(0x0002))){	// ARP应答
			entry->ip = packet->SendIP;
#ifdef DEBUG
			printf("thread_arp: sendip=%x, mac=%02X:%02X:%02X:%02X:%02X:%02X\n", entry->ip, packet->SendHa[0], packet->SendHa[1], packet->SendHa[2], packet->SendHa[3], packet->SendHa[4],
				packet->SendHa[5]);
#endif
			for (i = 0; i < 6; i++){
				entry->mac[i] = packet->SendHa[i];
			}
		}
		else{
			continue;
		}

		EnterCriticalSection(&cs);		// 处理链表
		struct ARPEntry *temp = arpTable;
		while (temp){
			if (temp->ip == entry->ip)
				break;
			temp = temp->next;
		}
		if (temp){						// 已经存在ARP项
			for (i = 0; i < 6; i++){
				temp->mac[i] = entry->mac[i];
			}
			free(entry);
		}
		else{
			entry->next = arpTable;
			arpTable = entry;
		}
		LeaveCriticalSection(&cs);

		free(pparam->data);
		pparam->data = NULL;
	}
}