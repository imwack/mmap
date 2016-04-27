#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/semaphore.h>
#include <net/ip.h>
#include <linux/in.h>
#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <net/tcp.h>
#include <linux/proc_fs.h>
#include <linux/if_arp.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/route.h>
#include <linux/proc_fs.h>
#include "pcap.h"

/*alloc one page. 4096 bytes*/
#define PAGE_ORDER 4
/*this value can get from PAGE_ORDER*/
#define PAGES_NUMBER 4
static int DUMP_PCAP = 1;

struct proc_dir_entry *proc_memshare_dir ;
unsigned long memaddr = 0;
unsigned long memaddr1 = 0;
unsigned long memsize= 0;

int currentfile = 0;
int offset = 0;
int offset1 = 0;
int free_size;
int free_size1;
int count = 0;
int count1 = 0;

#define PROC_MEMSHARE_DIR "memshare"
#define PROC_MEMSHARE_INFO "phymem_info"
#define PROC_DUMP_INFO "dump_info"
#define PROC_MMAP_FILE "mmap"
#define PROC_MMAP_FILE1 "mmap1"

static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;

static int proc_show_meminfo(struct seq_file *m, void *v) {
	//printk("proc_show_meminfo called...\n");
	seq_printf(m, "%08lx %lu %08lx\n",__pa(memaddr), memsize,__pa(memaddr1));
	return 0;
}

static int proc_open_meminfo(struct inode *inode, struct  file *file) {
	//printk("proc_open_meminfo called...\n");
	return single_open(file, proc_show_meminfo, NULL);
}

static const struct file_operations read_phymem_info_fops = { 
    .owner = THIS_MODULE, 
    .open = proc_open_meminfo, 
    .read = seq_read, 
    .llseek = seq_lseek, 
    .release = seq_release 
}; 

int proc_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long page;
    page = virt_to_phys((void *)memaddr) >> PAGE_SHIFT;

    if( remap_pfn_range(vma, vma->vm_start, page, (vma->vm_end - vma->vm_start), 
         vma->vm_page_prot) )
    {
        printk("remap failed...");
        return -1;
    }
    vma->vm_flags |= (VM_DONTDUMP|VM_DONTEXPAND);
    //printk("remap_pfn_rang page:[%lu] ok.\n", page);
    return 0;
}
int proc_mmap1(struct file *file, struct vm_area_struct *vma)
{
    unsigned long page;
    page = virt_to_phys((void *)memaddr1) >> PAGE_SHIFT;

    if( remap_pfn_range(vma, vma->vm_start, page, (vma->vm_end - vma->vm_start), 
         vma->vm_page_prot) )
    {
        printk("remap failed...");
        return -1;
    }
    vma->vm_flags |= (VM_DONTDUMP|VM_DONTEXPAND);
    //printk("remap_pfn_rang page:[%lu] ok.\n", page);
    return 0;
}
static int proc_show_dumpinfo(struct seq_file *m, void *v) {
	//printk("proc_show_dumpinfo called...\n");
	seq_printf(m, "%d %d %d %d\n",(currentfile?0:1),(currentfile?count:count1),currentfile,(currentfile?count1:count));		//输出当前文件和数量
	return 0;
}
static size_t proc_dumpinfo_open(struct inode *inode, struct  file *file) 
{
		//printk("proc_mmap_open called...\n");
		return single_open(file, proc_show_dumpinfo, NULL);
}

static const struct file_operations read_dumpmem_info_fops = { 
    .owner = THIS_MODULE, 
    .open = proc_dumpinfo_open, 
    .read = seq_read, 
    .llseek = seq_lseek, 
    .release = seq_release 
}; 
static const struct file_operations proc_mmap_fops = { 
    .owner = THIS_MODULE, 
    .mmap = proc_mmap
}; 
static const struct file_operations proc_mmap_fops1 = { 
    .owner = THIS_MODULE, 
    .mmap = proc_mmap1
}; 

int kks_proc_init(void)
{
         proc_memshare_dir = proc_mkdir(PROC_MEMSHARE_DIR, NULL);
         if(!proc_memshare_dir)
			return -1;
         if(!proc_create_data(PROC_MEMSHARE_INFO, 0, proc_memshare_dir, &read_phymem_info_fops,NULL))
			return -1;
         if(!proc_create_data(PROC_MMAP_FILE, 0, proc_memshare_dir, &proc_mmap_fops,NULL))
			return -1;
		 if(!proc_create_data(PROC_MMAP_FILE1, 0, proc_memshare_dir, &proc_mmap_fops1,NULL))
			return -1;
		 if(!proc_create_data(PROC_DUMP_INFO, 0, proc_memshare_dir, &read_dumpmem_info_fops,NULL))
			return -1;
		return 0;
}

void kks_proc_uninit(void)
{
		 remove_proc_entry(PROC_MMAP_FILE, proc_memshare_dir);
		 remove_proc_entry(PROC_MMAP_FILE1, proc_memshare_dir);
		 remove_proc_entry(PROC_MEMSHARE_INFO, proc_memshare_dir);
		 remove_proc_entry(PROC_DUMP_INFO, proc_memshare_dir);
         remove_proc_entry(PROC_MEMSHARE_DIR, NULL);
}


int CopyToSharedMem(struct sk_buff *skb)
{
		char *data;
		int DataLen = 0;
		struct iphdr *ih;
		ih = ip_hdr(skb);
		data = (char *)((char *)ih - ETH_HLEN);
		DataLen = htons(ih->tot_len) + ETH_HLEN;
		if(currentfile == 0)		//write file 0
		{	
				if(free_size < DataLen)
				{
						printk("File0 do not have enough memory...\n");
						currentfile = 1;
						offset1 = 0;
						count1 = 0;
						free_size1 = memsize;
						goto file1;
				}
				else
				{
						memcpy((void *)(memaddr + offset), data, DataLen);
						offset += DataLen;
						free_size -= DataLen;
						count++;
						printk("Packet[%d] Copy to shared memory[0],DataLen%d ,memory left :%d: \n",count,DataLen,free_size);
						return 0;
				}
		}

file1:			//write file 1
		if(free_size1 < DataLen)
		{
			printk("File1do not have enough memory...\n");
			currentfile = 0;
			offset = 0;
			count = 0;
			free_size = memsize;
		}
		else
		{
			memcpy((void *)(memaddr1 + offset1), data, DataLen);
			offset1 += DataLen;
			free_size1 -= DataLen;
			count1++;
			printk("Packet[%d] Copy to shared memory[1],DataLen%d ,memory left :%d: \n",count1,DataLen,free_size1);
		}
		return 0;
}

static unsigned int hook_local_in(unsigned int hooknum,
						struct sk_buff *skb,
						const struct net_device *in,
						const struct net_device *out,
						int (*okfn)(struct sk_buff *))
{
	struct iphdr *ih;
	struct tcphdr *th;

	ih = (struct iphdr *)skb->data;
	th = (struct tcphdr *)(skb->data + ih->ihl*4);
	if(DUMP_PCAP)
			CopyToSharedMem(skb);
	return NF_ACCEPT;
}

static unsigned int hook_local_out(unsigned int hooknum,
						struct sk_buff *skb,
						const struct net_device *in,
						const struct net_device *out,
						int (*okfn)(struct sk_buff *))
{
	//nothing to be done
	struct iphdr *ih;
	ih = ip_hdr(skb);  
	//printk(" hook_local_out\n");
	return NF_ACCEPT;
}

void nf_init(void)
{
		nfho_in.hook = hook_local_in;
		nfho_in.hooknum = NF_INET_PRE_ROUTING;
		nfho_in.pf = PF_INET;
		nfho_in.priority = NF_IP_PRI_FIRST;
		nf_register_hook(&nfho_in);

		nfho_out.hook = hook_local_out;
		nfho_out.hooknum = NF_INET_LOCAL_OUT;
		nfho_out.pf = PF_INET;
		nfho_out.priority = NF_IP_PRI_FIRST;
		nf_register_hook(&nfho_out);
}
void nf_uninit(void)
{
		nf_unregister_hook(&nfho_in);
		nf_unregister_hook(&nfho_out);
}
static int __init init(void)
{
        /*build proc dir "memshare"and two proc files: phymem_addr, phymem_size in the dir*/
		int ret;
		 ret = kks_proc_init();
		 if(ret==0)
			printk("Create proc file success!\n");
		else
		{
				printk("Create proc file failed!\n");
				return -1;
		}

        /*alloc one page*/
        memaddr =__get_free_pages(GFP_KERNEL, PAGE_ORDER);
        memaddr1 =__get_free_pages(GFP_KERNEL, PAGE_ORDER);
        if((!memaddr) || (!memaddr1))
        {
                 printk("Allocate memory failure!/n");
                 return -1;
        }
        else
        {
                 SetPageReserved(virt_to_page(memaddr));
				 SetPageReserved(virt_to_page(memaddr1));
                 memsize = PAGES_NUMBER * PAGE_SIZE;
                 free_size = memsize;
                 free_size1 = memsize;
                 currentfile = 0;			// 先写第一个文件
                 memset((void *)memaddr,0,memsize);
                 memset((void *)memaddr1,0,memsize);
                 printk("Allocate memory0 success!. The phy mem0 addr=%08lx, size=%lu\n", __pa(memaddr), memsize);
                 printk("Allocate memory1 success!. The phy mem1 addr=%08lx, size=%lu\n", __pa(memaddr1), memsize);
        }
        
        nf_init();
        return 0;
}

static void __exit fini(void)
{
         //printk("The content written by user is: %s\n", (unsigned char *) memaddr);
         ClearPageReserved(virt_to_page(memaddr));
         free_pages(memaddr, PAGE_ORDER);
         kks_proc_uninit();
		nf_uninit();
        return;
}
module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("wack");
MODULE_DESCRIPTION("Kernel memory share module.");
