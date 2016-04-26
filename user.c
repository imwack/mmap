#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

int main(int argc, char* argv[])
{

        unsigned long phymem_addr,phymem_addr1, phymem_size;
        char *map_addr;
        char s[4096];
        int fd,map_fd,i,len,count,currentfile;

        /*get the physical address & size of allocated memory in kernel*/
        fd = open("/proc/memshare/phymem_info", O_RDONLY);
        if(fd < 0)
        {
                printf("cannot open file /proc/memshare/phymem_info\n");
                return -1;
        }
        read(fd, s, sizeof(s));
        sscanf(s, "%lx %lu %lx", &phymem_addr,&phymem_size,&phymem_addr1);
        close(fd);
        printf("phymem_addr=%lx, phymem_addr1=%lx, phymem_size=%lu\n", phymem_addr, phymem_addr1,phymem_size);
        
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
         
         /*memory map*/
        if(currentfile ==0)
		{
				map_fd = open("/proc/memshare/mmap",  O_RDWR|O_SYNC);
				if(map_fd < 0)
				{
						printf("cannot open file /proc/memshare/mmap\n");
						return -1;
				}
				 map_addr = mmap(NULL, phymem_size, PROT_READ|PROT_WRITE, MAP_SHARED, map_fd, phymem_addr);
				 if(map_addr ==MAP_FAILED)
				 {
						perror("mmap");
						close(map_fd);
						return -1;
				 }
		 }
		 else{
			 	map_fd = open("/proc/memshare/mmap1",  O_RDWR|O_SYNC);
				if(map_fd < 0)
				{
						printf("cannot open file /proc/memshare/mmap1\n");
						return -1;
				}
				 map_addr = mmap(NULL, phymem_size, PROT_READ|PROT_WRITE, MAP_SHARED, map_fd, phymem_addr1);
				 if(map_addr ==MAP_FAILED)
				 {
						perror("mmap");
						close(map_fd);
						return -1;
				 }
		}
        //memcpy(map_addr, argv[1],sizeof(argv));
        printf("map addr :%s\n",map_addr);
        memcpy(s,map_addr,4096);
        printf("str is :%s \n",s);
        int ret = munmap(map_addr, phymem_size);
        if(ret)
        {
                printf("munmap failed:%d \n",ret);
         }
        close(map_fd);
        return 0;

}
