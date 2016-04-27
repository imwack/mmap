#ifndef _PCAP_H_
#define _PCAP_H_

// 为了保证在windows和linux下都能正常编译，放弃使用INT64或者_int_64
typedef short _Int16;
typedef long  _Int32;
typedef char Byte;
typedef unsigned int        UINT32, *PUINT32, UINT, *PUINT;
typedef signed int          INT32, *PINT32, INT, *PINT;

#define FILE_MAX_SIZE	32*1024 	//

typedef struct _FILE_OBJECT
{
	INT32 fd;
	void *mem;
	UINT32 len;
	UINT32 free;
}FILE_OBJECT, *PFILE_OBJECT;

// Pcap文件头
typedef struct __file_header
{
	_Int32	iMagic;
	_Int16	iMaVersion;
	_Int16	iMiVersion;
	_Int32	iTimezone;
	_Int32	iSigFlags;
	_Int32	iSnapLen;
	_Int32	iLinkType;
}pcap_hdr_t;

// 数据包头
struct __pkthdr
{
	_Int32		iTimeSecond;
	_Int32		iTimeSS;
	_Int32		iPLength;
	_Int32		iLength;
}pcaprec_hdr_t, *ppcaprec_hdr_t;

#pragma pack( pop)

#endif
