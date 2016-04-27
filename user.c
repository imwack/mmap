#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
//#include <sys/time.h>
#include <time.h>
#include "pcap.h"

#define PCAP_FILE_COUNT 2

unsigned long phymem_addr0,phymem_addr1, phymem_size;
char *map_addr0,*map_addr1;
char s[4096];
int fd,map_fd0,map_fd1,i,len,count,currentfile;
int StartDump = 0;
int suffix = 0;

PFILE_OBJECT PcapFile[PCAP_FILE_COUNT];

int GetMemInfo()
{
	/*get the physical address & size of allocated memory in kernel*/
        fd = open("/proc/memshare/phymem_info", O_RDONLY);
        if(fd < 0)
        {
                printf("cannot open file /proc/memshare/phymem_info\n");
                return -1;
        }
        read(fd, s, sizeof(s));
        sscanf(s, "%lx %lu %lx", &phymem_addr0,&phymem_size,&phymem_addr1);
        close(fd);
        printf("phymem_addr=%lx, phymem_addr1=%lx, phymem_size=%lu\n", phymem_addr0, phymem_addr1,phymem_size);
        return 0;
}

int GetDumpInfo()
{
	/*get dump info*/
		fd = open("/proc/memshare/dump_info", O_RDONLY);
        if(fd < 0)
        {
                printf("cannot open file /proc/memshare/dump_info\n");
                return -1;
        }
        read(fd, s, sizeof(s));
        sscanf(s, "%d %d\n",&currentfile, &count);
        close(fd);
        printf("current file :%d ,packet count: %d\n", currentfile, count);
        return 0;
}

int  InitMmapFile()
{
	//mmap file 0
			map_fd0= open("/proc/memshare/mmap",  O_RDWR|O_SYNC);
			if(map_fd0 < 0)
			{
					printf("cannot open file /proc/memshare/mmap\n");
					return -1;
			}
			 map_addr0 = mmap(NULL, phymem_size, PROT_READ|PROT_WRITE, MAP_SHARED, map_fd0, phymem_addr0);
			 if(map_addr0 ==MAP_FAILED)
			 {
					perror("mmap");
					close(map_fd0);
					return -1;
			 }
	//mmap file 1
			map_fd1 = open("/proc/memshare/mmap1",  O_RDWR|O_SYNC);
			if(map_fd1 < 0)
			{
					printf("cannot open file /proc/memshare/mmap1\n");
					return -1;
			}
			 map_addr1 = mmap(NULL, phymem_size, PROT_READ|PROT_WRITE, MAP_SHARED, map_fd1, phymem_addr1);
			 if(map_addr1 ==MAP_FAILED)
			 {
					perror("mmap");
					close(map_fd1);
					return -1;
			 }
			 return 0;
}

void UninitMmapFile()
{
			int ret ;
			ret = munmap(map_addr0, phymem_size);
			if(ret)
			{
					printf("munmap failed:%d \n",ret);
			 }
			 ret = munmap(map_addr1, phymem_size);
			if(ret)
			{
					printf("munmap failed:%d \n",ret);
			 }
			close(map_fd0);
			close(map_fd1);
}

PFILE_OBJECT CreateNewFileObject()
{
	char FileName[256];
	time_t nowtime;
	struct tm *ltime;
    pcap_hdr_t* pheader;
	time(&nowtime);
	ltime=localtime(&nowtime);

	PFILE_OBJECT new = malloc(sizeof(FILE_OBJECT));
	if(!new)
	{
		perror("malloc");
		return NULL;
	}
	suffix ++;
	sprintf(FileName, "%d%d%d%d%d%d-%d.pcap",1900+ltime->tm_year,
	       1+ltime->tm_mon,ltime->tm_mday,ltime->tm_hour,ltime->tm_min,ltime->tm_sec,suffix);

	printf("finame: %s\n",FileName);
	new->fd = open(FileName,O_CREAT|O_RDWR,S_IRUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);//fopen(FileName, "w+");
	if(new->fd < 0)
	{
		printf("Create New FileObject failed");
		free(new);
		return NULL;
	}
    new->free = FILE_MAX_SIZE;
	new->len = 0;

	ftruncate(new->fd , FILE_MAX_SIZE);

	new->mem = (void *)mmap(0, FILE_MAX_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED,new->fd,0);
	if (new->mem == MAP_FAILED)
	{
		perror("mmap");
		free(new);
		close(new->fd);
		return NULL;
	}
	//printf("mem:%p\n",new->mem);
	memset(new->mem, 0 ,FILE_MAX_SIZE);

    pheader=(pcap_hdr_t*)malloc(sizeof(pcap_hdr_t));
    pheader->iMagic=0xa1b2c3d4;
    pheader->iMaVersion=2;
    pheader->iMiVersion=4;
    pheader->iTimezone=0;
    pheader->iSigFlags=0;
    pheader->iSnapLen=65535;
    pheader->iLinkType=1;

    memcpy(new->mem, (char *)pheader, sizeof(pcap_hdr_t));
    new->len += sizeof(pcap_hdr_t);
    new->free -= sizeof(pcap_hdr_t);
    free(pheader);
	return new;
}

int InitPcapFile()
{
		int i,j;
		for(i = 0; i < PCAP_FILE_COUNT; i++)
		{
			PcapFile[i] = CreateNewFileObject();
			if(!PcapFile[i])
			{
				for(j = 0; j < i;j++)
					free(PcapFile[j]);
				printf("CreateNewFileObject failed\n");
				return -1;
			}
		}
		return 0;
}

void DumpPcapFile()
{
		struct ethhdr eth;
		struct iphdr iph;
		INT32	i;
		struct timezone tz;
	    struct timeval tv;
	    pcaprec_hdr_t rheader;
	    UINT32 packetlen;
	    char *pmem;
	    
	    if(PcapFile[0]->free < ring->offset)
	    {
	    	KksDebug("1111111111\n");
	    	CloseFileObject(PcapFile[0]);
	    	PcapFile[0] = PcapFile[1];
	    	PcapFile[1] = CreateNewFileObject();
	    }
	
	    ring->offset = 0;
	    pmem = (char *)((char *)ring + sizeof(MEMBLOCK));
	    for(i = 0; i < ring->count; i++ )
	    {
			//eth = (PETH_HEAD)(ring->mem + ring->offset);
	
	    	eth = (PETH_HEAD)(pmem + ring->offset);
			iph = (PIP_HEADER)((char *)eth + 14);
			packetlen = htons(iph->TotalLength) + 14;
			gettimeofday(&tv,&tz);
			rheader.ts_sec = tv.tv_sec;
			rheader.ts_usec = tv.tv_usec;
			rheader.incl_len = packetlen;
			rheader.orig_len = packetlen;
			memcpy(PcapFile[0]->mem + PcapFile[0]->len, &rheader, sizeof(pcaprec_hdr_t));
			PcapFile[0]->len += sizeof(pcaprec_hdr_t);
			PcapFile[0]->free -= sizeof(pcaprec_hdr_t);
	
			memcpy(PcapFile[0]->mem + PcapFile[0]->len, (char *)(eth), packetlen);
			PcapFile[0]->len += packetlen;
			PcapFile[0]->free -= packetlen;
	
			ring->count --;
			ring->offset += packetlen;
	    }
	
	    memset(ring, 0, SHARED_MEMORY_SIZE >> 1 );
	    ring->free_size = (UINT32)((SHARED_MEMORY_SIZE >> 1) - sizeof(MEMBLOCK));
	    ring->state = UNDEFINED;
}
int main(int argc, char* argv[])
{

		int ret;
        ret = GetMemInfo();
        if(ret !=0)
        {
			printf("Get Memory info failed ,exit...\n");
			return -1;
		}
		
		ret = InitPcapFile();
		if(ret !=0)
        {
			printf("Init Pcap File failed ,exit...\n");
			return -1;
		}
		
		ret = InitMmapFile();
		if(ret !=0)
        {
			printf("Init Pcap File failed ,exit...\n");
			return -1;
		}
		
		while(1)
		{
				sleep(1);		//delay 1s
				ret = GetDumpInfo();	//get current file and pcap number
				if(ret !=0)
				{
					printf("Get Dump info failed ,exit...\n");
					return -1;
				}
				 /*memory map*/
				if(currentfile ==0)
				{
						//noting to be done...
						if(StartDump)
						{
								DumpPcapFile();
						}
				 }
				 else{
						if(!StartDump)
						{
							StartDump = 1;		//After file0 been writen over, start dump
							printf("Start dump pcap...\n");
						}
						DumpPcapFile();
					
				}
				
		}
		UninitMmapFile();
        return 0;

}
