#include "CDlgRouter.h"
#include "resource.h"

typedef struct Param{
	HANDLE hEvent;
	PVOID data;
}Param, *PParam;

CHAR errbuf[PCAP_ERRBUF_SIZE];	// 错误信息缓冲区
pcap_if_t *alldevs;		// 指向设备链表的指针
pcap_if_t *dev;
pcap_t *adhandle;
pcap_addr *devaddr1, *devaddr2;
BYTE LocalMAC[6];
CRITICAL_SECTION cs;		// arp表的临界区
ARPEntry *arpTable;
IPEntry *routeTable;

INT initNet();
VOID clearNet();
VOID GetMAC(DWORD, BYTE[6], int);
VOID thread_capture(PVOID);
VOID thread_arp(PVOID);

#define DEBUG
#define TEST
//#define SINGLE
#define WM_ROUTE WM_USER+100

// 普通函数

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


// 类函数

BEGIN_MESSAGE_MAP(CDlgRouter, CDialog)
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDC_ADDROUTE, addRoute)
	ON_BN_CLICKED(IDC_REMOVEROUTE, removeRoute)
	//ON_MESSAGE(WM_ROUTE, route)
END_MESSAGE_MAP()

CDlgRouter::CDlgRouter(CWnd *pParent)
:CDialog(IDD_SIMPLEROUTE, pParent)
{
#ifdef DEBUG
	alloc_or_attach();
#endif;
	if (initNet() < 0){	// 获取网卡信息，选择网卡，获取MAC地址与IP地址信息
		SendMessage(WM_CLOSE);
		return;
	}
	InitializeCriticalSection(&cs);
	_beginthread(thread_capture, 0, NULL);	// 创建路由进程
	
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
	if (own){		// 当获取本机MAC地址时，抓包线程还未启动，只能自己抓
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
		else if (bfind){
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

// 负责抓包
VOID thread_capture(PVOID pvoid){
	DWORD netmask;
	struct bpf_program fcode;

	HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);		// 用于通知arp线程有数据包处理
	Param param;
	param.hEvent = hEvent;
	param.data = NULL;
	// 启动arp线程处理arp包
	_beginthread(thread_arp, 0, (PVOID)&param);

	if (dev->addresses != NULL){
		netmask = ((struct sockaddr_in *)dev->addresses->netmask)->sin_addr.S_un.S_addr;
	}
	else{
		netmask = 0xffffff;
	}
	// 设置过滤器：IPv4，目的IP不是自己，目的MAC是自己或者ARP
	char filter[200];
	sprintf_s(filter, "(ip and not dst host %s", inet_ntoa(((struct sockaddr_in*)devaddr1->addr)->sin_addr));
	sprintf_s(filter, "%s and not dst host %s", filter, inet_ntoa(((struct sockaddr_in*)devaddr2->addr)->sin_addr));
	sprintf_s(filter, "%s and ether dst %02X:%02X:%02X:%02X:%02X:%02X)", filter, LocalMAC[0], LocalMAC[1], LocalMAC[2], LocalMAC[3], LocalMAC[4], LocalMAC[5]);
	sprintf_s(filter, "%s or (arp and (dst host %s", filter, inet_ntoa(((struct sockaddr_in*)devaddr1->addr)->sin_addr));
	sprintf_s(filter, "%s or dst host %s))", filter, inet_ntoa(((struct sockaddr_in*)devaddr2->addr)->sin_addr));
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
			extern CDlgRouter *prouter;
			MessageBox(NULL, TEXT("LLL"), 0, 0);
			prouter->PostMessageW(WM_ROUTE, 0, (LPARAM)data);
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
	return;
}


VOID thread_arp(PVOID pvoid){
	PParam pparam = (PParam)pvoid;
	while (1){
		WaitForSingleObject(pparam->hEvent, INFINITE);	// 等待thread_route的通知
		ARPFrame_t *packet = (ARPFrame_t *)pparam->data;
		int i;
		struct ARPEntry *entry = (struct ARPEntry*)malloc(sizeof(ARPEntry));
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
	return;
}

void CDlgRouter::DoDataExchange(CDataExchange *pDX){
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LOG, m_loglist);
	DDX_Control(pDX, IDC_ROUTETABLE, m_routelist);
	DDX_Control(pDX, IDC_SUBMASK, m_submask);
	DDX_Control(pDX, IDC_NEXTHOP, m_nexthop);
	DDX_Control(pDX, IDC_DSTIP, m_dstip);
}

BOOL CDlgRouter::OnInitDialog(){
	TCHAR szbuf[100];
	CDialog::OnInitDialog();
	m_loglist.AddString(CharToTchar(dev->description));
	wsprintf(szbuf, TEXT("MAC: %02X:%02X:%02X:%02X:%02X:%02X"), LocalMAC[0], LocalMAC[1], LocalMAC[2], LocalMAC[3], LocalMAC[4], LocalMAC[5]);
	m_loglist.AddString(szbuf);
	wsprintf(szbuf, TEXT("IP addr1: %s"), CharToTchar(inet_ntoa(((sockaddr_in *)devaddr1->addr)->sin_addr)));
	m_loglist.AddString(szbuf);
	wsprintf(szbuf, TEXT("IP addr2: %s"), CharToTchar(inet_ntoa(((sockaddr_in *)devaddr2->addr)->sin_addr)));
	m_loglist.AddString(szbuf);
	return TRUE;
}


VOID CDlgRouter::addRoute(){
	DWORD submask, dstip, nexthop;
	struct IPEntry *routry = NULL;
	m_submask.GetAddress(submask);
	m_nexthop.GetAddress(nexthop);
	m_dstip.GetAddress(dstip);

	// 添加到内部路由表
	routry = (struct IPEntry*)malloc(sizeof(struct IPEntry));
	if (routry == NULL){
		winprintf("Out of memory");
		SendMessage(WM_CLOSE);
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
	sprintf_s(buf, "%s", inet_ntoa(taddr));
	taddr.S_un.S_addr = routry->dstip;
	sprintf_s(buf, "%s -- %s", buf, inet_ntoa(taddr));
	taddr.S_un.S_addr = routry->nexthop;
	sprintf_s(buf, "%s -- %s", buf, inet_ntoa(taddr));
	wsprintf(szbuf, TEXT("%s %s"), CharToTchar(buf), nexthop ? 0 : TEXT("(直接投递)"));
	m_routelist.AddString(szbuf);
}

VOID CDlgRouter::removeRoute(){
	int i;
	// 获取当前选项
	if ((i = m_routelist.GetCurSel()) == LB_ERR){		// 当前没有选中任何选项
		return;
	}

	// 删除外部显示
	int n = m_routelist.DeleteString(i);	// n是剩下的项的个数

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

LRESULT CDlgRouter::route(WPARAM wParam, LPARAM data){
	IPFrame_t *packet = (IPFrame_t *)data;
	DWORD dstip = packet->IPHeader.DstIP;
	// 由于Wpcap的过滤器，dstip一定不是本机IP
	// 遍历路由表
	struct IPEntry *temp = routeTable;
	struct IPEntry *entry = NULL;
	if (packet->FrameHeader.FrameType == htons(0x0806))		// ARP包直接扔掉
		return NULL;
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
	TCHAR buf[100];
	struct in_addr taddr;
	wsprintf(buf, TEXT("Packet %d:"), ++count);
	taddr.S_un.S_addr = packet->IPHeader.SrcIP;
	wsprintf(buf, TEXT("%s From %s"), buf, CharToTchar(inet_ntoa(taddr)));
	taddr.S_un.S_addr = dstip;
	wsprintf(buf, TEXT("%s to %s"), buf, CharToTchar(inet_ntoa(taddr)));
	taddr.S_un.S_addr = entry->nexthop;
	wsprintf(buf, TEXT("%s, nextHop=%s"), buf, CharToTchar(inet_ntoa(taddr)));
	m_loglist.AddString(buf);
out:
	free((void *)data);
	return NULL;
}

void CDlgRouter::OnClose(){
	clearNet();
#ifdef DEBUG
	freeCon();
#endif
	DeleteCriticalSection(&cs);
	DestroyWindow();
}