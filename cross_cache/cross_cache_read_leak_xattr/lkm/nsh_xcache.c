/*
 * nsh_xcache.c - uaf read for leak via ret2buddy for linux 7.0
 * Antonius - bluedragonsec.com 
 * victim = kmalloc(512, GFP_KERNEL) not dedicated cache.
 * reclaimer: pipe_buffer ring, buf->ops = anon_pipe_buf_ops (.text)
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/ioctl.h>
#include <linux/mm.h>
#include <linux/io.h>
#define NSH_DEVICE_NAME "nsh_target"
#define NSH_MAGIC       'N'
#define NSH_ALLOC       _IOW(NSH_MAGIC, 0x01, struct nsh_slot)
#define NSH_FREE    	_IOW(NSH_MAGIC, 0x02, struct nsh_slot)
#define NSH_READ    	_IOWR(NSH_MAGIC, 0x04, struct nsh_io)
#define NSH_INFO   	 	_IOR(NSH_MAGIC, 0x05, struct nsh_info)
#define NSH_RESET   	_IO(NSH_MAGIC, 0x06)
#define NSH_DBG     	_IOWR(NSH_MAGIC, 0x08, struct nsh_dbg)
#define OBJ_SIZE   		512
#define MAX_SLOTS  		16384
struct nsh_slot  { __u32 slot; __u32 _pad; };
struct nsh_io    { __u32 slot; __u32 off; __u32 len; __u32 _pad; __u8 buf[512]; };
struct nsh_info  { __u32 alloc_total; __u32 obj_size; __u32 _r1; __u32 max_slots; };
struct nsh_dbg   { __u32 slot; __u32 page_type; __u64 kaddr; __u64 pfn; __u64 phys; };
static DEFINE_MUTEX(nsh_lock);
static void *slots[MAX_SLOTS];

static long nsh_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	long ret = 0;
	struct nsh_slot s;
	struct nsh_io *kio = NULL;
	unsigned long head = 0;
	unsigned int i;

	mutex_lock(&nsh_lock);
	switch (cmd) {
	case NSH_ALLOC:
		if (copy_from_user(&s,(void __user*)arg,sizeof(s))){
			ret=-EFAULT;
			break;
		}
		if (s.slot >= MAX_SLOTS) {
			ret =-EINVAL;
			break;
		}
		if (slots[s.slot]){
			ret=-EEXIST;
			break;
		}
		/* kmalloc GFP_KERNEL -> kmalloc-rnd-512 (has sheaf) */
		slots[s.slot]=kmalloc(OBJ_SIZE,GFP_KERNEL);
		if(!slots[s.slot]){
			ret=-ENOMEM;
			break;
		}
		memset(slots[s.slot],0,OBJ_SIZE);
		break;
	case NSH_FREE:
		if (copy_from_user(&s,(void __user*)arg,sizeof(s))){
			ret=-EFAULT;
			break;
		}
		if (s.slot >= MAX_SLOTS){
			ret=-EINVAL;
			break;
		}
		if (!slots[s.slot]) {
			ret =-ENOENT;
			break;
		}
		kfree(slots[s.slot]);
		break;
	case NSH_READ: 
		kio = kmalloc(sizeof(*kio),GFP_KERNEL);
		if(!kio){
			ret=-ENOMEM;
			break;
		}
		if (copy_from_user(kio,(void __user*)arg,sizeof(*kio))){
			ret=-EFAULT;
			break;
		}
		if (kio->slot>=MAX_SLOTS || !slots[kio->slot]) {
			ret=-ENOENT;
			break;
		}
		if (kio->len>sizeof(kio->buf) || (u64)kio->off+kio->len>OBJ_SIZE){
			ret=-EINVAL;
			break;
		}
		memcpy(kio->buf,(char*)slots[kio->slot]+kio->off,kio->len);
		if (copy_to_user((void __user*)arg,kio,sizeof(*kio))) 
			ret=-EFAULT;
		break;
	case NSH_INFO: {
		struct nsh_info info = { .alloc_total=OBJ_SIZE, .obj_size=OBJ_SIZE, .max_slots=MAX_SLOTS };
		if (copy_to_user((void __user*)arg,&info,sizeof(info))) 
			ret=-EFAULT;
		break;
	}
	case NSH_RESET: {
		for (i = 0; i < MAX_SLOTS; i++) 
			slots[i]=NULL;
		break;
	}
	case NSH_DBG: {
		struct nsh_dbg d; 
		void *obj;

		if (copy_from_user(&d,(void __user*)arg,sizeof(d))){
			ret=-EFAULT;
			break;
		}
		if (d.slot >= MAX_SLOTS){
			ret=-EINVAL;
			break;
		}
		obj = slots[d.slot];
		d.kaddr = (u64)(unsigned long)obj;
		if (obj){
			struct page *pg = virt_to_page(obj);
			d.phys = virt_to_phys(obj); d.pfn = d.phys>>PAGE_SHIFT;
			if (pg) {
				head = READ_ONCE(pg->compound_head);
				if (head&1) 
					pg=(struct page*)(head-1);
				d.page_type=pg->page_type;
			} 
			else 
				d.page_type=0;
		} 
		else { 
			d.phys=d.pfn=0; 
			d.page_type=0; 
		}
		if (copy_to_user((void __user*)arg,&d,sizeof(d))) 
			ret=-EFAULT;
		break;
	}
	default:
		ret=-ENOTTY;
	}
	kfree(kio);
	mutex_unlock(&nsh_lock);

	return ret;
}

static const struct file_operations nsh_fops = {
	.owner=THIS_MODULE, .unlocked_ioctl=nsh_ioctl, .compat_ioctl=nsh_ioctl,
};
static struct miscdevice nsh_dev = {
	.minor=MISC_DYNAMIC_MINOR, .name=NSH_DEVICE_NAME, .fops=&nsh_fops, .mode=0666,
};

static int __init nsh_init(void) {
	if (misc_register(&nsh_dev)) 
		return -ENODEV;
	
	return 0;
}
static void __exit nsh_exit(void) {
	misc_deregister(&nsh_dev);
}

module_init(nsh_init);
module_exit(nsh_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius - bluedragonsec.com");
MODULE_DESCRIPTION("UAF read .text leak via cross cache: kmalloc-rnd-512 victim -> buddy -> pipe_buffer ring");
