#include <afxwin.h>

#pragma pack(1)
typedef struct FrameHeader_t{	// frame�ײ�
	BYTE DescMAC[6];
	BYTE SrcMAC[6];
	WORD FrameType;
}FrameHeader_t;

typedef struct ARPFrame_t{
	FrameHeader_t	FrameHeader;
	WORD			HardwareType;	// Ӳ������
	WORD			ProtocolType;	// Э������
	BYTE			HLen;			// Ӳ����ַ����
	BYTE			PLen;			// Э���ַ����
	WORD			Operation;		// ����
	BYTE			SendHa[6];		// ԴMAC��ַ
	DWORD			SendIP;			// ԴIP��ַ
	BYTE			RecvHa[6];		// Ŀ��MAC��ַ
	DWORD			RecvIP;			// Ŀ��IP
}ARPFrame_t;

typedef struct IPHeader_t{	// IPv4�ײ�
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
};		// ·�ɱ�, �������ݾ�Ϊ������

struct ARPEntry{
	DWORD ip;
	BYTE mac[6];
	struct ARPEntry *next;
};