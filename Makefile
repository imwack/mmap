#General Purpose Makefile for Linux Kernel module by guoqingbo

#KERN_DIR = /home/linux-kernel-2.6.37
#KERN_DIR = /usr/src/$(shell uname -r)
KERN_DIR = /lib/modules/$(shell uname -r)/build

obj-m += mmap.o

all:
	make -C $(KERN_DIR) M=$(shell pwd) modules   

clean:                                 
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.symvers *.order


