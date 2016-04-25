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

#define PROC_MEMSHARE_DIR "memshare"
#define PROC_MEMSHARE_INFO "phymem_info"
#define PROC_MMAP_FILE "mmap"

/*alloc one page. 4096 bytes*/
#define PAGE_ORDER 0
/*this value can get from PAGE_ORDER*/
#define PAGES_NUMBER 1

struct proc_dir_entry *proc_memshare_dir ;
unsigned long kernel_memaddr = 0;
unsigned long kernel_memsize= 0;

static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;

int proc_mmap(struct file *filp, struct vm_area_struct *vma)
{
    unsigned long page;
    page = virt_to_phys((void *)kernel_memaddr) >> PAGE_SHIFT;

    if( remap_pfn_range(vma, vma->vm_start, page, (vma->vm_end - vma->vm_start), 
         vma->vm_page_prot) )
    {
        printk("remap failed...");
        return -1;
    }
    vma->vm_flags |= (VM_DONTDUMP|VM_DONTEXPAND);
    printk("remap_pfn_rang page:[%lu] ok.\n", page);
    return 0;
}

static int proc_show_meminfo(struct seq_file *m, void *v) {
  seq_printf(m, "%08lx %lu\n",__pa(kernel_memaddr), kernel_memsize);
  return 0;
}

static int proc_open_meminfo(struct inode *inode, struct  file *file) {
  return single_open(file, proc_show_meminfo, NULL);
}

static const struct file_operations read_phymem_info_fops = { 
    .owner = THIS_MODULE, 
    .open = proc_open_meminfo, 
    .read = seq_read, 
    .llseek = seq_lseek, 
    .release = seq_release 
}; 


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
//输出源目IP地址
	printk(" IN : from %pI4 to %pI4\n",&ih->saddr,&ih->daddr);
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
static const struct file_operations proc_mmap_fops = { 
    .owner = THIS_MODULE, 
    .mmap = proc_mmap
}; 
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
         proc_memshare_dir = proc_mkdir(PROC_MEMSHARE_DIR, NULL);
         proc_create_data(PROC_MEMSHARE_INFO, 0, proc_memshare_dir, &read_phymem_info_fops,NULL);
         proc_create_data(PROC_MMAP_FILE, 0, proc_memshare_dir, &proc_mmap_fops,NULL);

        /*alloc one page*/
         kernel_memaddr =__get_free_pages(GFP_KERNEL, PAGE_ORDER);
        if(!kernel_memaddr)
        {
                 printk("Allocate memory failure!/n");
        }
        else
        {
                 SetPageReserved(virt_to_page(kernel_memaddr));
                 kernel_memsize = PAGES_NUMBER * PAGE_SIZE;
                 memset((void *)kernel_memaddr,0,4096);
                 printk("Allocate memory success!. The phy mem addr=%08lx, size=%lu\n", __pa(kernel_memaddr), kernel_memsize);
        }
        
        nf_init();
        return 0;
}

static void __exit fini(void)
{
         printk("The content written by user is: %s\n", (unsigned char *) kernel_memaddr);
         ClearPageReserved(virt_to_page(kernel_memaddr));
         free_pages(kernel_memaddr, PAGE_ORDER);
         remove_proc_entry(PROC_MEMSHARE_INFO, proc_memshare_dir);
         remove_proc_entry(PROC_MEMSHARE_DIR, NULL);
		nf_uninit();
        return;
}
module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("wack");
MODULE_DESCRIPTION("Kernel memory share module.");
