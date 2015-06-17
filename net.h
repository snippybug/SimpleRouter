#include <afxwin.h>

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

struct IPEntry{
	DWORD submask;
	DWORD dstip;
	DWORD nexthop;
	struct IPEntry *next;
};		// 路由表, 所有数据均为网络序

struct ARPEntry{
	DWORD ip;
	BYTE mac[6];
	struct ARPEntry *next;
};