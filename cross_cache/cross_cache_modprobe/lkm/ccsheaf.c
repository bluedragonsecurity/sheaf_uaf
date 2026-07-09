/*
 * ccsheaf.c uaf lkm for cross cache demo - kernel 7.0
 * by: Antonius (w1sdom / sw0rdm4n) - bluedragonsec.com
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/printk.h>
typedef void (*ccs_complete_fn)(void *ctx);
struct ccs_req {
	int           slot;
	unsigned long cookie;
	unsigned long len;
	void __user  *ubuf;
};
#define DEVICE_NAME   "ccsheaf"
#define CLASS_NAME    "ccsheaf"
#define CCS_MAX_SLOTS   8192      /* groom 960 + spray 1200  */
#define CCS_OBJ_SIZE    512       /* kmalloc-512, sheaf_capacity = 28  */
#define CCS_IOC_MAGIC  'C'
#define CCS_ALLOC      _IOWR(CCS_IOC_MAGIC, 1, struct ccs_req)  /* GFP_KERNEL -> kmalloc-rnd-512 (victim) */
#define CCS_ALLOC_CG   _IOWR(CCS_IOC_MAGIC, 2, struct ccs_req)  /* GFP_KERNEL_ACCOUNT -> kmalloc-cg-512 (reclaimer) */
#define CCS_FREE       _IOW (CCS_IOC_MAGIC, 3, struct ccs_req)  
#define CCS_PEEK       _IOWR(CCS_IOC_MAGIC, 4, struct ccs_req)  /* UAF read  (leak) */
#define CCS_POKE       _IOW (CCS_IOC_MAGIC, 5, struct ccs_req)  /* UAF write  */
#define CCS_SYNC       _IOW (CCS_IOC_MAGIC, 6, struct ccs_req)  
struct ccs_object {
	ccs_complete_fn complete;   
	void           *ctx;        
	unsigned long  *wp;        
	unsigned long   wv;        
	u32             seq;        
	u32             _pad;     
	unsigned char   data[CCS_OBJ_SIZE - 0x28];
};
/* state  */
static int major;
static struct class  *ccs_class;
static struct device *ccs_dev;
static struct ccs_object *slots[CCS_MAX_SLOTS];
static DEFINE_MUTEX(ccs_lock);

static long do_alloc(struct ccs_req *r, gfp_t gfp) {
	struct ccs_object *obj;

	if (r->slot < 0 || r->slot >= CCS_MAX_SLOTS)
		return -EINVAL;
	obj = kmalloc(sizeof(*obj), gfp);
	if (!obj)
		return -ENOMEM;
	obj->complete = (ccs_complete_fn)kfree;  /* pointer kernel -> leak  */
	obj->ctx      = NULL;
	obj->wp       = &obj->wv;   /* default self writeback  */
	obj->wv       = 0;
	obj->seq      = (u32)r->cookie;
	obj->_pad     = 0;
	slots[r->slot] = obj;

	return 0;
}

static long do_free(struct ccs_req *r) {
	if (r->slot < 0 || r->slot >= CCS_MAX_SLOTS)
		return -EINVAL;
	if (!slots[r->slot])
		return -ENOENT;
	kfree(slots[r->slot]);

	return 0;
}

static long do_peek(struct ccs_req *r) {
	struct ccs_object *obj;
	unsigned char kbuf[sizeof(struct ccs_object)];
	unsigned long n;

	if (r->slot < 0 || r->slot >= CCS_MAX_SLOTS)
		return -EINVAL;
	obj = slots[r->slot];     
	if (!obj)
		return -ENOENT;
	n = r->len;
	if (n > sizeof(struct ccs_object))
		n = sizeof(struct ccs_object);
	memcpy(kbuf, obj, n);   
	if (copy_to_user(r->ubuf, kbuf, n))
		return -EFAULT;

	return 0;
}

static long do_poke(struct ccs_req *r) {
	struct ccs_object *obj;
	unsigned char kbuf[sizeof(struct ccs_object)];
	unsigned long n;

	if (r->slot < 0 || r->slot >= CCS_MAX_SLOTS)
		return -EINVAL;
	obj = slots[r->slot];    
	if (!obj)
		return -ENOENT;
	n = r->len;
	if (n > sizeof(struct ccs_object))
		n = sizeof(struct ccs_object);
	if (copy_from_user(kbuf, r->ubuf, n))
		return -EFAULT;
	memcpy(obj, kbuf, n);     

	return 0;
}

static long do_sync(struct ccs_req *r) {
	struct ccs_object *obj;

	if (r->slot < 0 || r->slot >= CCS_MAX_SLOTS)
		return -EINVAL;
	obj = slots[r->slot];     
	if (!obj)
		return -ENOENT;
	if (obj->wp)
		*(obj->wp) = obj->wv; 

	return 0;
}

static long ccs_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	struct ccs_req r;
	long ret;

	if (copy_from_user(&r, (void __user *)arg, sizeof(r)))
		return -EFAULT;
	mutex_lock(&ccs_lock);
	switch (cmd) {
	case CCS_ALLOC:    
		ret = do_alloc(&r, GFP_KERNEL);          
		break;
	case CCS_ALLOC_CG: 
		ret = do_alloc(&r, GFP_KERNEL_ACCOUNT);  
		break;
	case CCS_FREE:     
		ret = do_free(&r);                       
		break;
	case CCS_PEEK:     
		ret = do_peek(&r);                       
		break;
	case CCS_POKE:     
		ret = do_poke(&r);                       
		break;
	case CCS_SYNC:     
		ret = do_sync(&r);                       
		break;
	default:           
		ret = -ENOTTY;                           
		break;
	}
	mutex_unlock(&ccs_lock);

	return ret;
}

static int ccs_open(struct inode *i, struct file *f) { return 0; }

static int ccs_release(struct inode *i, struct file *f) { return 0; }

static const struct file_operations ccs_fops = {
	.owner          = THIS_MODULE,
	.open           = ccs_open,
	.release        = ccs_release,
	.unlocked_ioctl = ccs_ioctl,
	.compat_ioctl   = ccs_ioctl,
};

static char *ccs_devnode(const struct device *dev, umode_t *mode) {
	if (mode)
		*mode = 0666;

	return NULL;
}

static int __init ccs_init(void) {
	major = register_chrdev(0, DEVICE_NAME, &ccs_fops);
	if (major < 0)
		return major;
	ccs_class = class_create(CLASS_NAME);
	if (IS_ERR(ccs_class)) {
		unregister_chrdev(major, DEVICE_NAME);
		return PTR_ERR(ccs_class);
	}
	ccs_class->devnode = ccs_devnode;
	ccs_dev = device_create(ccs_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
	if (IS_ERR(ccs_dev)) {
		class_destroy(ccs_class);
		unregister_chrdev(major, DEVICE_NAME);
		return PTR_ERR(ccs_dev);
	}
	
	return 0;
}

static void __exit ccs_exit(void) {
	int i;

	mutex_lock(&ccs_lock);
	for (i = 0; i < CCS_MAX_SLOTS; i++)
		slots[i] = NULL;
	mutex_unlock(&ccs_lock);
	device_destroy(ccs_class, MKDEV(major, 0));
	class_destroy(ccs_class);
	unregister_chrdev(major, DEVICE_NAME);
}

module_init(ccs_init);
module_exit(ccs_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius (w1sdom / sw0rdm4n) - bluedragonsec.com");
MODULE_DESCRIPTION("Vulnerable LKM - SLUB sheaves cross cache UAF, modprobe_path payload");
