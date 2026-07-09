/*
 * pagejack.c - lkm with uaf write vulner for pagejack test
 * victim =  kmalloc-512 GFP_KERNEL (kmalloc-rnd-512, sheaf cap=28)
 * antonius - bluedragonsec.com
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
#include <linux/mm.h>
#define DEVNAME    "pagejack"
#define OBJ_SIZE   512
#define MAX_SLOTS  16384
typedef void (*ccs_complete_fn)(void *ctx);
struct ccs_object {
	ccs_complete_fn complete;  
	void           *ctx;        
	u32             seq;        
	u32             _pad;                              
	char            data[OBJ_SIZE - 0x18];
};
struct ccs_req { int slot; __u32 len; __u64 ubuf; };
struct ccs_rng { int from; int to; };  
struct ccs_dbg { int slot; __u64 kaddr; __u64 pfn; __u64 phys; __u32 page_type; };
#define CCS_ALLOC      _IOWR('C', 0x01, struct ccs_req) /* victim (rnd-512) */
#define CCS_POKE       _IOWR('C', 0x02, struct ccs_req) /* UAF write */
#define CCS_PEEK       _IOWR('C', 0x03, struct ccs_req) 
#define CCS_FREE       _IOWR('C', 0x04, struct ccs_req) 
#define CCS_DBG        _IOWR('C', 0x06, struct ccs_dbg)
#define CCS_FIRE       _IOWR('C', 0x07, struct ccs_req) 
#define CCS_GROOM      _IOWR('C', 0x09, struct ccs_rng)
#define CCS_FREE_RANGE _IOWR('C', 0x0a, struct ccs_rng) 
#define CCS_RESET      _IOWR('C', 0x0b, struct ccs_req)
static void *slots[MAX_SLOTS];
static DEFINE_MUTEX(ccs_lock);
static int ccs_major;
static struct class *ccs_class;
static struct device *ccs_dev;
static atomic_t ccs_seq = ATOMIC_INIT(0);
#define CCS_DEFAULT_COMPLETE ((ccs_complete_fn)kfree)

static int alloc_one(int slot) {
	struct ccs_object *obj;

	if (slot < 0 || slot >= MAX_SLOTS)
		return -EINVAL;
	if (slots[slot])
		return -EBUSY;
	obj = kmalloc(OBJ_SIZE, GFP_KERNEL);
	if (!obj)
		return -ENOMEM;
	obj->complete = CCS_DEFAULT_COMPLETE;
	obj->ctx = NULL;
	obj->seq  = atomic_inc_return(&ccs_seq);
	slots[slot] = obj;

	return 0;
}

static void free_one_dangling(int slot) {
	if (slot < 0 || slot >= MAX_SLOTS || !slots[slot])
		return;
	kfree(slots[slot]);
}

static void free_one_clean(int slot) {
	if (slot < 0 || slot >= MAX_SLOTS || !slots[slot])
		return;
	kfree(slots[slot]);
	slots[slot] = NULL;
}

static long ccs_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	long ret = 0;
	struct ccs_dbg d;
	void *obj;
	struct page *pg;
	unsigned long head;
	struct ccs_rng rng;
	int i;
	struct ccs_req req;

	if (cmd == CCS_DBG) {
		if (copy_from_user(&d, (void __user *)arg, sizeof(d)))
			return -EFAULT;
		if (d.slot < 0 || d.slot >= MAX_SLOTS)
			return -EINVAL;
		mutex_lock(&ccs_lock);
		obj = slots[d.slot];
		d.kaddr = (unsigned long)obj;
		if (obj) {
			pg = virt_to_page(obj);
			d.phys = virt_to_phys(obj);
			d.pfn  = d.phys >> PAGE_SHIFT;
			if (pg) {
				head = READ_ONCE(pg->compound_head);
				if (head & 1)
					pg = (struct page *)(head - 1);
				d.page_type = pg->page_type;
			} 
			else 
				d.page_type = 0;
		} 
		else { 
			d.phys = d.pfn = 0; 
			d.page_type = 0; 
		}
		mutex_unlock(&ccs_lock);
		if (copy_to_user((void __user *)arg, &d, sizeof(d)))
			return -EFAULT;
		return 0;
	}
	if (cmd == CCS_GROOM || cmd == CCS_FREE_RANGE) {
		if (copy_from_user(&rng, (void __user *)arg, sizeof(rng)))
			return -EFAULT;
		if (rng.from < 0 || rng.to > MAX_SLOTS || rng.from >= rng.to)
			return -EINVAL;
		mutex_lock(&ccs_lock);
		if (cmd == CCS_GROOM) {
			for (i = rng.from; i < rng.to; i++) {
				ret = alloc_one(i);
				if (ret && ret != -EBUSY) 
					break;
				ret = 0;
			}
		} 
		else { 
			for (i = rng.from; i < rng.to; i++)
				free_one_clean(i);
		}
		mutex_unlock(&ccs_lock);
		return ret;
	}
	{
		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		if (req.slot < 0 || req.slot >= MAX_SLOTS)
			return -EINVAL;
		if ((cmd == CCS_PEEK || cmd == CCS_POKE) && req.len > OBJ_SIZE)
			return -EINVAL;
		mutex_lock(&ccs_lock);
		switch (cmd) {
		case CCS_ALLOC:
			ret = alloc_one(req.slot);
			break;
		case CCS_FREE:   /* dangling free */
			if (!slots[req.slot]) { 
				ret = -ENOENT; 
				break; 
			}
			free_one_dangling(req.slot);
			break;
		case CCS_RESET:  
			slots[req.slot] = NULL;
			break;
		case CCS_PEEK:
			if (!slots[req.slot]) { 
				ret = -ENOENT; 
				break; 
			}
			if (copy_to_user((void __user *)req.ubuf, slots[req.slot], req.len))
				ret = -EFAULT;
			break;
		case CCS_POKE:
			if (!slots[req.slot]) { 
				ret = -ENOENT; 
				break; 
			}
			if (copy_from_user(slots[req.slot], (void __user *)req.ubuf, req.len))
				ret = -EFAULT;
			break;
		case CCS_FIRE: {
			struct ccs_object *obj = slots[req.slot];
			if (!obj) { 
				ret = -ENOENT; 
				break; 
			}
			if (obj->complete)
				obj->complete(obj->ctx);
			break;
		}
		default:
			ret = -ENOTTY;
		}
		mutex_unlock(&ccs_lock);
	}

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
MODULE_DESCRIPTION("Cross cache page UAF (kernel 7.0)");
