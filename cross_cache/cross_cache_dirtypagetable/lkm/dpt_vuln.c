/*
 * vulnerable lkm for cross-cache UAF demo using dirtypagetable
 * for linux 7.0
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
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/io.h>
#define DEVICE_NAME  	 "dpt_vuln"
#define CLASS_NAME       "dpt_vuln"
#define DPT_MAX_SLOTS    8192
#define DPT_OBJ_SIZE     128   
struct dpt_object {
	unsigned long        marker;   
	unsigned long        pad1;   
	unsigned long        pad2;     
	unsigned long        pad3;     
	u32                  seq;      
	u32                  _pad;     
	unsigned char        data[DPT_OBJ_SIZE - 0x28]; 
};
struct dpt_req {
	int            	     slot;
	unsigned long        cookie;
	unsigned long        len;
	void __user          *ubuf;
};
struct dpt_dbg {
	int                  slot;
	__u64                kaddr; /* kernel virtual address object  */
	__u64                phys; /* virt_to_phys(obj) */
	__u64          		 pfn; /* phys >> PAGE_SHIFT */
	__u64                phys_base; /* arch/x86 phys_base (va to pa conversion) */
	__u64            	 v2p_in;    
	__u64                v2p_out;   
};
#define DPT_IOC_MAGIC    'D'
#define DPT_ALLOC        _IOWR(DPT_IOC_MAGIC, 1, struct dpt_req)
#define DPT_FREE         _IOW (DPT_IOC_MAGIC, 2, struct dpt_req)
#define DPT_PEEK         _IOWR(DPT_IOC_MAGIC, 3, struct dpt_req)
#define DPT_POKE         _IOW (DPT_IOC_MAGIC, 4, struct dpt_req)
#define DPT_DBG          _IOWR(DPT_IOC_MAGIC, 5, struct dpt_dbg)
static int major;
static struct class      *dpt_class;
static struct device     *dpt_dev;
static struct kmem_cache *dpt_cache;
static void              *slots[DPT_MAX_SLOTS];
static DEFINE_MUTEX(dpt_lock);
extern unsigned long phys_base;    

static void dpt_ctor(void *p) { memset(p, 0, DPT_OBJ_SIZE); }

static long do_alloc(struct dpt_req *r) {
	struct dpt_object *obj;

	if (r->slot < 0 || r->slot >= DPT_MAX_SLOTS)
		return -EINVAL;
	obj = kmem_cache_alloc(dpt_cache, GFP_KERNEL);
	if (!obj)
		return -ENOMEM;
	obj->marker = (unsigned long)kfree;  
	obj->pad1   = 0;
	obj->pad2   = 0;
	obj->pad3   = 0;
	obj->seq    = (u32)r->cookie;
	obj->_pad   = 0;
	slots[r->slot] = obj;

	return 0;
}

static long do_free(struct dpt_req *r) {
	if (r->slot < 0 || r->slot >= DPT_MAX_SLOTS)
		return -EINVAL;
	if (!slots[r->slot])
		return -ENOENT;
	kmem_cache_free(dpt_cache, slots[r->slot]);
	 
	return 0;
}

/* UAF read for leak */
static long do_peek(struct dpt_req *r) {
	void *obj;
	unsigned char kbuf[DPT_OBJ_SIZE];
	unsigned long n;

	if (r->slot < 0 || r->slot >= DPT_MAX_SLOTS)
		return -EINVAL;
	obj = slots[r->slot];
	if (!obj)
		return -ENOENT;
	n = r->len;
	if (n > DPT_OBJ_SIZE)
		n = DPT_OBJ_SIZE;
	memcpy(kbuf, obj, n);
	if (copy_to_user(r->ubuf, kbuf, n))
		return -EFAULT;

	return 0;
}

/* UAF write: for writing PTE entry after  page reclaimed as PTE page */
static long do_poke(struct dpt_req *r) {
	void *obj;
	unsigned char kbuf[DPT_OBJ_SIZE];
	unsigned long n;

	if (r->slot < 0 || r->slot >= DPT_MAX_SLOTS)
		return -EINVAL;
	obj = slots[r->slot];
	if (!obj)
		return -ENOENT;
	n = r->len;
	if (n > DPT_OBJ_SIZE)
		n = DPT_OBJ_SIZE;
	if (copy_from_user(kbuf, r->ubuf, n))
		return -EFAULT;
	memcpy(obj, kbuf, n);

	return 0;
}

static long do_dbg(struct dpt_dbg *d) {
	void *obj;

	if (d->slot < 0 || d->slot >= DPT_MAX_SLOTS)
		return -EINVAL;
	obj = slots[d->slot];
	d->kaddr = (unsigned long)obj;
	d->phys_base = phys_base;
	if (obj) {
		d->phys = virt_to_phys(obj);
		d->pfn  = d->phys >> PAGE_SHIFT;
	} 
	else {
		d->phys = 0;
		d->pfn  = 0;
	}
	/* virt-to-phys oracle: translate arbitrary kernel VA to  PA */
	if (d->v2p_in == 0xDEADUL) {
		if (obj) {
			struct page *pg = virt_to_page(obj);
			d->v2p_out = PageSlab(pg) ? 1 : 0;
		} 
		else {
			d->v2p_out = 99;  /* no object */
		}
	} 
	else if (d->v2p_in) {
		d->v2p_out = virt_to_phys((void *)d->v2p_in);
	} 
	else {
		d->v2p_out = 0;
	}

	return 0;
}

static long dpt_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	long ret;
	struct dpt_req r;

	if (cmd == DPT_DBG) {
		struct dpt_dbg d;
		if (copy_from_user(&d, (void __user *)arg, sizeof(d)))
			return -EFAULT;
		mutex_lock(&dpt_lock);
		ret = do_dbg(&d);
		mutex_unlock(&dpt_lock);
		if (ret) 
			return ret;
		if (copy_to_user((void __user *)arg, &d, sizeof(d)))
			return -EFAULT;
		return 0;
	}
	{
		if (copy_from_user(&r, (void __user *)arg, sizeof(r)))
			return -EFAULT;
		mutex_lock(&dpt_lock);
		switch (cmd) {
		case DPT_ALLOC: 
			ret = do_alloc(&r); 
			break;
		case DPT_FREE:  
			ret = do_free(&r);  
			break;
		case DPT_PEEK:  
			ret = do_peek(&r);  
			break;
		case DPT_POKE:  
			ret = do_poke(&r);  
			break;
		default:        
			ret = -ENOTTY;      
			break;
		}
		mutex_unlock(&dpt_lock);
		return ret;
	}
}

static int dpt_open(struct inode *i, struct file *f)    { return 0; }

static int dpt_release(struct inode *i, struct file *f) { return 0; }

static const struct file_operations dpt_fops = {
	.owner          = THIS_MODULE,
	.open           = dpt_open,
	.release        = dpt_release,
	.unlocked_ioctl = dpt_ioctl,
	.compat_ioctl   = dpt_ioctl,
};

static char *dpt_devnode(const struct device *dev, umode_t *mode) {
	if (mode) 
		*mode = 0666;

	return NULL;
}

static int __init dpt_init(void) {
	major = register_chrdev(0, DEVICE_NAME, &dpt_fops);
	if (major < 0) 
		return major;
	dpt_class = class_create(CLASS_NAME);
	if (IS_ERR(dpt_class)) {
		unregister_chrdev(major, DEVICE_NAME);
		return PTR_ERR(dpt_class);
	}
	dpt_class->devnode = dpt_devnode;
	dpt_dev = device_create(dpt_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
	if (IS_ERR(dpt_dev)) {
		class_destroy(dpt_class);
		unregister_chrdev(major, DEVICE_NAME);
		return PTR_ERR(dpt_dev);
	}
	dpt_cache = kmem_cache_create("dpt_victim", DPT_OBJ_SIZE, 0,
				      SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT | SLAB_PANIC,
				      dpt_ctor);
	pr_info("phys_base=0x%lx\n",  phys_base);

	return 0;
}

static void __exit dpt_exit(void) {
	int i;

	mutex_lock(&dpt_lock);
	for (i = 0; i < DPT_MAX_SLOTS; i++)
		slots[i] = NULL;
	mutex_unlock(&dpt_lock);
	device_destroy(dpt_class, MKDEV(major, 0));
	class_destroy(dpt_class);
	unregister_chrdev(major, DEVICE_NAME);
	if (dpt_cache)
		kmem_cache_destroy(dpt_cache);
}

module_init(dpt_init);
module_exit(dpt_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius (w1sdom) - bluedragonsec.com");
MODULE_DESCRIPTION("DirtyPageTable Demo for linux 7.0");
