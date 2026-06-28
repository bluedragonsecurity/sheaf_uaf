/*
 * ccsheaf.c - uaf read and write vulner for cross cache
 * Victim  : kmalloc-rnd-NN-512
 * Reclaim :  kmalloc-cg-512 
 * kernel 7.0 
 * Antonius - bluedragonsec.com
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/ioctl.h>
#include <linux/io.h>
#define DEVNAME    "ccsheaf"
#define OBJ_SIZE   512
#define MAX_SLOTS  8192
typedef void (*ccs_complete_fn)(void *ctx);
struct ccs_object {
	ccs_complete_fn complete;   /* leak  */
	void           *ctx;        
	u32             seq;        
	u32             _pad;      
	char            data[OBJ_SIZE - 0x18];
};
struct ccs_req { int slot; __u32 len; __u64 ubuf; };
struct ccs_dbg { int slot; __u64 kaddr; __u64 pfn; __u64 phys; __u32 page_type; };
static void *slots[MAX_SLOTS];
static DEFINE_MUTEX(ccs_lock);
static int ccs_major;
static struct class *ccs_class;
static struct device *ccs_dev;
static atomic_t ccs_seq = ATOMIC_INIT(0);
#define CCS_ALLOC  _IOWR('C', 0x01, struct ccs_req)
#define CCS_FREE   _IOWR('C', 0x04, struct ccs_req)   
#define CCS_PEEK   _IOWR('C', 0x03, struct ccs_req) 
#define CCS_POKE   _IOWR('C', 0x02, struct ccs_req)   /* UAF write (set fptr)   */
#define CCS_FIRE   _IOWR('C', 0x07, struct ccs_req)  
#define CCS_ALLOC_CG _IOWR('C', 0x08, struct ccs_req) /* reclaimer kmalloc-cg   */
#define CCS_DBG    _IOWR('C', 0x06, struct ccs_dbg)  
#define CCS_DEFAULT_COMPLETE ((ccs_complete_fn)kfree)

static long ccs_ioctl(struct file *f, unsigned int cmd, unsigned long arg)  {
	struct ccs_req req;
	struct page *pg;
	long ret = 0;

	if (cmd == CCS_DBG) {
		struct ccs_dbg d;
		void *obj;
		if (copy_from_user(&d, (void __user *)arg, sizeof(d)))
			return -EFAULT;
		if (d.slot < 0 || d.slot >= MAX_SLOTS)
			return -EINVAL;
		obj = slots[d.slot];
		d.kaddr = (unsigned long)obj;
		if (obj) {
			pg = virt_to_page(obj);
			d.phys = virt_to_phys(obj);
			d.pfn  = d.phys >> PAGE_SHIFT;
			d.page_type = pg ? pg->page_type : 0;
		} 
		else { 
			d.phys = d.pfn = 0; 
			d.page_type = 0; 
		}
		if (copy_to_user((void __user *)arg, &d, sizeof(d)))
			return -EFAULT;
		return 0;
	}
	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.slot < 0 || req.slot >= MAX_SLOTS)
		return -EINVAL;
	if ((cmd == CCS_PEEK || cmd == CCS_POKE) && req.len > OBJ_SIZE)
		return -EINVAL;
	mutex_lock(&ccs_lock);
	switch (cmd) {
	case CCS_ALLOC: {
		struct ccs_object *obj = kmalloc(OBJ_SIZE, GFP_KERNEL);

		if (!obj) { 
			ret = -ENOMEM; 
			break; 
		}
		obj->complete = CCS_DEFAULT_COMPLETE;   /* &kfree -> leak */
		obj->ctx      = NULL;
		obj->seq      = atomic_inc_return(&ccs_seq);
		slots[req.slot] = obj;
		break;
	}
	case CCS_ALLOC_CG: {
		struct ccs_object *obj = kmalloc(OBJ_SIZE, GFP_KERNEL_ACCOUNT);
		if (!obj) { 
			ret = -ENOMEM; 
			break; 
		}
		obj->complete = CCS_DEFAULT_COMPLETE;
		obj->ctx      = NULL;
		obj->seq      = atomic_inc_return(&ccs_seq);
		slots[req.slot] = obj;
		break;
	}
	case CCS_FREE:
		if (!slots[req.slot]) { 
			ret = -ENOENT; 
			break; 
		}
		kfree(slots[req.slot]);
		break;
	case CCS_PEEK:   /* UAF read */
		if (!slots[req.slot]) { 
			ret = -ENOENT; 
			break; 
		}
		if (copy_to_user((void __user *)req.ubuf, slots[req.slot], req.len))
			ret = -EFAULT;
		break;
	case CCS_POKE:   /* UAF write */
		if (!slots[req.slot]) { 
			ret = -ENOENT; 
			break; 
		}
		if (copy_from_user(slots[req.slot], (void __user *)req.ubuf, req.len))
			ret = -EFAULT;
		break;
	case CCS_FIRE: { /* indirect call for LPE via function pointer hijack */
		struct ccs_object *obj = slots[req.slot];
		if (!obj) { 
			ret = -ENOENT; 
			break; 
		}
		if (obj->complete)
			obj->complete(obj->ctx);   /* commit_creds(&init_cred) */
		break;
	}
	default:
		ret = -ENOTTY;
	}
	mutex_unlock(&ccs_lock);

	return ret;
}

static const struct file_operations ccs_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ccs_ioctl,
	.compat_ioctl = ccs_ioctl,
};

static char *ccs_devnode(const struct device *dev, umode_t *mode) { 
	if (mode) *mode = 0666; 
		return NULL; 
}

static int __init ccs_init(void) {
	ccs_major = register_chrdev(0, DEVNAME, &ccs_fops);
	if (ccs_major < 0) 
		return ccs_major;
	ccs_class = class_create(DEVNAME);
	if (IS_ERR(ccs_class)) { 
		unregister_chrdev(ccs_major, DEVNAME); 
		return PTR_ERR(ccs_class); 
	}
	ccs_class->devnode = ccs_devnode;
	ccs_dev = device_create(ccs_class, NULL, MKDEV(ccs_major, 0), NULL, DEVNAME);
	
	return 0;
}
static void __exit ccs_exit(void) {
	int i;

	device_destroy(ccs_class, MKDEV(ccs_major, 0));
	class_destroy(ccs_class);
	unregister_chrdev(ccs_major, DEVNAME);
	for (i = 0; i < MAX_SLOTS; i++) 
		slots[i] = NULL;
}

module_init(ccs_init);
module_exit(ccs_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius (w1sdom) - bluedragonsec.com");
MODULE_DESCRIPTION("Cross cache UAF pOc LKM via fptr hijack + _text leak for SLUB sheaves kernel 7.0");
