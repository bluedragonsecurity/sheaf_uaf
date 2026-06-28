/*
 * ccblind.c - uaf vulnerable for linux  7.0
 * Antonius (w1sdom) - bluedragonsec.com - linux 7.0
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
#include <linux/cred.h>
#include <linux/vmalloc.h>

struct cc_req {
	int           idx;     
	unsigned long cookie;
	unsigned long len;
	void __user  *ubuf;
};
struct cc_run { int lo; int hi; };
static int major;
static struct class  *cc_class;
static struct device *cc_dev;
static struct kmem_cache *cc_cache;
static void **handles;                 /* CC_MAX_HANDLES pointers (vmalloc) */
static DEFINE_MUTEX(cc_lock);

#define DEVICE_NAME   "ccblind"
#define CLASS_NAME    "ccblind"
#define CC_MAX_HANDLES   65536
/* cred_jar: sizeof(struct cred) aligned to 192 (kmalloc-192) */
#define CC_OBJ_SZ   192
#define CC_IOC_MAGIC  'B'
#define CC_ALLOC    _IOWR(CC_IOC_MAGIC, 1, struct cc_req)
#define CC_WRITE    _IOW (CC_IOC_MAGIC, 2, struct cc_req)  /* UAF write(blind) */
#define CC_READ     _IOWR(CC_IOC_MAGIC, 3, struct cc_req)  /* UAF read (probe) */
#define CC_FREE     _IOW (CC_IOC_MAGIC, 4, struct cc_req)
#define CC_ALLOC_RUN _IOW(CC_IOC_MAGIC, 5, struct cc_run)  /* alloc [lo,hi) */
#define CC_FREE_RUN  _IOW(CC_IOC_MAGIC, 6, struct cc_run)  /* free  [lo,hi) */

static void cc_ctor(void *p) { memset(p, 0, CC_OBJ_SZ); }

static long do_alloc_one(int idx) {
	void *obj;

	if (idx < 0 || idx >= CC_MAX_HANDLES) 
		return -EINVAL;
	obj = kmem_cache_alloc(cc_cache, GFP_KERNEL);
	if (!obj) 
		return -ENOMEM;
	memset(obj, 0, CC_OBJ_SZ);
	handles[idx] = obj;
	
	return 0;
}

static long do_free_one(int idx) {
	if (idx < 0 || idx >= CC_MAX_HANDLES) 
		return -EINVAL;
	if (!handles[idx]) 
		return -ENOENT;
	kmem_cache_free(cc_cache, handles[idx]);  
	
	return 0;
}

static long cc_ioctl(struct file *f, unsigned int cmd, unsigned long arg){
	long ret = 0;

	if (cmd == CC_ALLOC_RUN || cmd == CC_FREE_RUN) {
		struct cc_run r;
		int i;
		if (copy_from_user(&r, (void __user *)arg, sizeof(r))) 
			return -EFAULT;
		if (r.lo < 0 || r.hi > CC_MAX_HANDLES || r.lo >= r.hi) 
			return -EINVAL;
		mutex_lock(&cc_lock);
		for (i = r.lo; i < r.hi; i++) {
			if (cmd == CC_ALLOC_RUN) { 
				if (do_alloc_one(i)) { 
					ret = -ENOMEM; 
					break; 
				} 
			}
			else                       
				do_free_one(i);
		}
		mutex_unlock(&cc_lock);
		return ret;
	}

	{
		struct cc_req r;
		unsigned char kbuf[256];
		unsigned long n;
		void *obj;
		
		if (copy_from_user(&r, (void __user *)arg, sizeof(r))) 
			return -EFAULT;
		mutex_lock(&cc_lock);
		switch (cmd) {
		case CC_ALLOC: 
			ret = do_alloc_one(r.idx); 
			break;
		case CC_FREE:  
			ret = do_free_one(r.idx);  
			break;
		case CC_WRITE:
			if (r.idx < 0 || r.idx >= CC_MAX_HANDLES) { 
				ret = -EINVAL; 
				break; 
			}
			obj = handles[r.idx];
			if (!obj) { 
				ret = -ENOENT; 
				break; 
			}
			n = r.len; 
			if (n > CC_OBJ_SZ) 
				n = CC_OBJ_SZ; 
			if (n > sizeof(kbuf)) 
				n = sizeof(kbuf);
			if (copy_from_user(kbuf, r.ubuf, n)) { 
				ret = -EFAULT; 
				break; 
			}
			memcpy(obj, kbuf, n);
			break;
		case CC_READ:
			if (r.idx < 0 || r.idx >= CC_MAX_HANDLES) { 
				ret = -EINVAL; 
				break; 
			}
			obj = handles[r.idx];
			if (!obj) { 
				ret = -ENOENT; 
				break; 
			}
			n = r.len; 
			if (n > CC_OBJ_SZ) 
				n = CC_OBJ_SZ; 
			if (n > sizeof(kbuf)) 
				n = sizeof(kbuf);
			memcpy(kbuf, obj, n);
			if (copy_to_user(r.ubuf, kbuf, n)) 
				ret = -EFAULT;
			break;
		default: ret = -ENOTTY;
		}
		mutex_unlock(&cc_lock);
		return ret;
	}
}
static int cc_open(struct inode *i, struct file *f) { return 0; }
static int cc_release(struct inode *i, struct file *f){ return 0; }
static const struct file_operations cc_fops = {
	.owner=THIS_MODULE, .open=cc_open, .release=cc_release,
	.unlocked_ioctl=cc_ioctl, .compat_ioctl=cc_ioctl,
};
static char *cc_devnode(const struct device *dev, umode_t *mode) { if (mode) *mode = 0666; return NULL; }

static int __init cc_init(void) {
	handles = vzalloc(sizeof(void *) * CC_MAX_HANDLES);
	if (!handles) 
		return -ENOMEM;
	/* 192B, align to cred_jar (kmalloc-192/HWCACHE), ctor = non merge */
	cc_cache = kmem_cache_create("ccblind_vic",CC_OBJ_SZ, 0, SLAB_NO_MERGE | SLAB_HWCACHE_ALIGN, cc_ctor);
	if (!cc_cache) { 
		vfree(handles); 
		return -ENOMEM; 
	}
	major = register_chrdev(0, DEVICE_NAME, &cc_fops);
	if (major < 0) { 
		kmem_cache_destroy(cc_cache); 
		vfree(handles); 
		return major; 
	}
	cc_class = class_create(CLASS_NAME);
	if (IS_ERR(cc_class)) { 
		unregister_chrdev(major, DEVICE_NAME); 
		kmem_cache_destroy(cc_cache); 
		vfree(handles); 
		return PTR_ERR(cc_class); 
	}
	cc_class->devnode = cc_devnode;
	cc_dev = device_create(cc_class, NULL, MKDEV(major,0), NULL, DEVICE_NAME);
	if (IS_ERR(cc_dev)) { 
		class_destroy(cc_class); 
		unregister_chrdev(major, DEVICE_NAME); 
		kmem_cache_destroy(cc_cache); 
		vfree(handles); 
		return PTR_ERR(cc_dev); 
	}
	
	return 0;
}

static void __exit cc_exit(void) {
	device_destroy(cc_class, MKDEV(major,0));
	class_destroy(cc_class);
	unregister_chrdev(major, DEVICE_NAME);
	kmem_cache_destroy(cc_cache);
	vfree(handles);
	pr_info("ccblind: unloaded\n");
}

module_init(cc_init);
module_exit(cc_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius (w1sdom) - bluedragonsec.com");
MODULE_DESCRIPTION("Vulnerable LKM for kernel 7");
