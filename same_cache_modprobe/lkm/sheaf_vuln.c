/*
 * sheaf_vuln.c - lkm with uaf for same cache reclaim
 * same cache reclaim via sheaf
 * lpe via modprobe
 * Antonius - bluedragonsec.com
 * linux kernel 7.0
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
#define DEVICE_NAME   "sheafy"
#define CLASS_NAME    "sheafy"
#define SHEAFY_MAX_HANDLES   16
#define SHEAFY_DATA_LEN      216   /* object_size 256 (cap=28) */
#define SHEAFY_IOC_MAGIC  's'
#define SHEAFY_ALLOC   _IOWR(SHEAFY_IOC_MAGIC, 1, struct sheafy_req)
#define SHEAFY_WRITE   _IOW(SHEAFY_IOC_MAGIC, 2, struct sheafy_req)
#define SHEAFY_READ    _IOWR(SHEAFY_IOC_MAGIC, 3, struct sheafy_req)
#define SHEAFY_FREE    _IOW(SHEAFY_IOC_MAGIC, 4, struct sheafy_req)
#define SHEAFY_SYNC    _IOW(SHEAFY_IOC_MAGIC, 5, struct sheafy_req)
struct sheafy_obj {
	int  (*log_fn)(const char *fmt, ...);  
	unsigned long *wp;                     
	unsigned long  wv;                     
	unsigned long  cookie;                
	unsigned long  len;                    
	unsigned char  data[SHEAFY_DATA_LEN];  
};
struct sheafy_req {
	int           idx;
	unsigned long cookie;
	unsigned long len;
	void __user  *ubuf;
};
static int major;
static struct class  *sheafy_class;
static struct device *sheafy_dev;
static struct kmem_cache *sheafy_cache;
static struct sheafy_obj *handles[SHEAFY_MAX_HANDLES];
static DEFINE_MUTEX(sheafy_lock);

static long do_alloc(struct sheafy_req *r) {
	struct sheafy_obj *obj;

	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES)
		return -EINVAL;
	obj = kmem_cache_alloc(sheafy_cache, GFP_KERNEL);
	if (!obj)
		return -ENOMEM;
	obj->log_fn = _printk;    
	obj->wp     = &obj->wv;    
	obj->wv     = 0;
	obj->cookie = r->cookie;
	obj->len    = 0;
	handles[r->idx] = obj;
	
	return 0;
}

static long do_write(struct sheafy_req *r) {
	struct sheafy_obj *obj;
	unsigned char kbuf[sizeof(struct sheafy_obj)];
	unsigned long n;

	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES)
		return -EINVAL;
	obj = handles[r->idx]; /* dangling */
	if (!obj)
		return -ENOENT;
	n = r->len;
	if (n > sizeof(struct sheafy_obj))
		n = sizeof(struct sheafy_obj);
	if (copy_from_user(kbuf, r->ubuf, n))
		return -EFAULT;
	memcpy(obj, kbuf, n); /* uaf write */

	return 0;
}

/*
 * uaf read - info leak
 */
static long do_read(struct sheafy_req *r) {
	struct sheafy_obj *obj;
	unsigned char kbuf[sizeof(struct sheafy_obj)];
	unsigned long n;

	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES)
		return -EINVAL;
	obj = handles[r->idx];   /* dangling */
	if (!obj)
		return -ENOENT;
	n = r->len;
	if (n > sizeof(struct sheafy_obj))
		n = sizeof(struct sheafy_obj);
	memcpy(kbuf, obj, n);   
	if (copy_to_user(r->ubuf, kbuf, n))
		return -EFAULT;

	return 0;
}

static long do_free(struct sheafy_req *r) {
	struct sheafy_obj *obj;

	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES)
		return -EINVAL;
	obj = handles[r->idx];
	if (!obj)
		return -ENOENT;
	kmem_cache_free(sheafy_cache, obj);

	return 0;
}

/*
 * uaf write
*/
static long do_sync(struct sheafy_req *r) {
	struct sheafy_obj *obj;

	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES)
		return -EINVAL;
	obj = handles[r->idx];   /* dangling */
	if (!obj)
		return -ENOENT;
	if (obj->wp)
		*(obj->wp) = obj->wv;   

	return 0;
}

static long sheafy_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	struct sheafy_req r;
	long ret;

	if (copy_from_user(&r, (void __user *)arg, sizeof(r)))
		return -EFAULT;
	mutex_lock(&sheafy_lock);
	switch (cmd) {
	case SHEAFY_ALLOC: 
		ret = do_alloc(&r); 
		break;
	case SHEAFY_WRITE: 
		ret = do_write(&r); 
		break;
	case SHEAFY_READ:  
		ret = do_read(&r);  
		break;
	case SHEAFY_FREE:  
		ret = do_free(&r);  
		break;
	case SHEAFY_SYNC:  
		ret = do_sync(&r);  
		break;
	default:           
		ret = -ENOTTY;      
		break;
	}
	mutex_unlock(&sheafy_lock);

	return ret;
}

static int sheafy_open(struct inode *i, struct file *f)  { return 0; }
static int sheafy_release(struct inode *i, struct file *f) { return 0; }

static const struct file_operations sheafy_fops = {
	.owner          = THIS_MODULE,
	.open           = sheafy_open,
	.release        = sheafy_release,
	.unlocked_ioctl = sheafy_ioctl,
	.compat_ioctl   = sheafy_ioctl,
};

static char *sheafy_devnode(const struct device *dev, umode_t *mode) {
	if (mode)
		*mode = 0666;

	return NULL;
}

static int __init sheafy_init(void) {
	/*
	 * dedicated cache
	 * object_size = 256 -> sheaf_capacity = 28. Free -> free_to_pcs()
	 */
	sheafy_cache = kmem_cache_create("sheafy_ctx", sizeof(struct sheafy_obj), 0, 0, NULL  /* no ctor */);
	if (!sheafy_cache)
		return -ENOMEM;
	major = register_chrdev(0, DEVICE_NAME, &sheafy_fops);
	if (major < 0) {
		kmem_cache_destroy(sheafy_cache);
		return major;
	}
	sheafy_class = class_create(CLASS_NAME);
	if (IS_ERR(sheafy_class)) {
		unregister_chrdev(major, DEVICE_NAME);
		kmem_cache_destroy(sheafy_cache);
		return PTR_ERR(sheafy_class);
	}
	sheafy_class->devnode = sheafy_devnode;
	sheafy_dev = device_create(sheafy_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
	if (IS_ERR(sheafy_dev)) {
		class_destroy(sheafy_class);
		unregister_chrdev(major, DEVICE_NAME);
		kmem_cache_destroy(sheafy_cache);
		return PTR_ERR(sheafy_dev);
	}

	return 0;
}

static void __exit sheafy_exit(void) {
	int i;

	mutex_lock(&sheafy_lock);
	for (i = 0; i < SHEAFY_MAX_HANDLES; i++)
		handles[i] = NULL;
	mutex_unlock(&sheafy_lock);
	device_destroy(sheafy_class, MKDEV(major, 0));
	class_destroy(sheafy_class);
	unregister_chrdev(major, DEVICE_NAME);
	kmem_cache_destroy(sheafy_cache);
}

module_init(sheafy_init);
module_exit(sheafy_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius - bluedragonsec.com");
MODULE_DESCRIPTION("Vulnerable LKM: SLUB sheaves same cache UAF - kernel 7.0");
