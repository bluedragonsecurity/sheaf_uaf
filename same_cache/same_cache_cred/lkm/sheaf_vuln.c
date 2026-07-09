/*
 * sheaf_vuln.c - same cache UAF  reclaim (cred overwrite) - for linux 7.0
 * Antonius (w1sdom) - bluedragonsec.com / linux 7.0
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
struct sheafy_req {
	int           idx;
	unsigned long cookie;
	unsigned long len;
	void __user  *ubuf;
};
#define DEVICE_NAME   		 "sheafy"
#define CLASS_NAME    		 "sheafy"
#define SHEAFY_MAX_HANDLES   1024
#define SHEAFY_OBJ_SZ   	 (sizeof(struct cred))
#define SHEAFY_IOC_MAGIC  	 's'
#define SHEAFY_ALLOC   		 _IOWR(SHEAFY_IOC_MAGIC, 1, struct sheafy_req)
#define SHEAFY_WRITE   		 _IOW(SHEAFY_IOC_MAGIC, 2, struct sheafy_req)
#define SHEAFY_READ    		 _IOWR(SHEAFY_IOC_MAGIC, 3, struct sheafy_req)
#define SHEAFY_FREE    		 _IOW(SHEAFY_IOC_MAGIC, 4, struct sheafy_req)
static int major;
static struct class  *sheafy_class;
static struct device *sheafy_dev;
static struct kmem_cache *sheafy_cache;
static void *handles[SHEAFY_MAX_HANDLES];
static DEFINE_MUTEX(sheafy_lock);

static long do_alloc(struct sheafy_req *r) {
	void *obj;

	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES) 
		return -EINVAL;
	obj = kmem_cache_alloc(sheafy_cache, GFP_KERNEL);
	if (!obj) 
		return -ENOMEM;
	memset(obj, 0, SHEAFY_OBJ_SZ);
	handles[r->idx] = obj;

	return 0;
}

static long do_write(struct sheafy_req *r) {
	void *obj;
	unsigned char kbuf[512];
	unsigned long n;

	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES) 
		return -EINVAL;
	obj = handles[r->idx];
	if (!obj) 
		return -ENOENT;
	n = r->len;
	if (n > SHEAFY_OBJ_SZ) 
		n = SHEAFY_OBJ_SZ;
	if (n > sizeof(kbuf)) 
		n = sizeof(kbuf);
	if (copy_from_user(kbuf, r->ubuf, n)) 
		return -EFAULT;
	memcpy(obj, kbuf, n);   /* uaf write */

	return 0;
}

static long do_read(struct sheafy_req *r) {
	void *obj;
	unsigned char kbuf[512];
	unsigned long n;

	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES) 
		return -EINVAL;
	obj = handles[r->idx];
	if (!obj) 
		return -ENOENT;
	n = r->len;
	if (n > SHEAFY_OBJ_SZ) 
		n = SHEAFY_OBJ_SZ;
	if (n > sizeof(kbuf)) 
		n = sizeof(kbuf);
	memcpy(kbuf, obj, n);   /* uaf read */
	if (copy_to_user(r->ubuf, kbuf, n)) 
		return -EFAULT;

	return 0;
}

static long do_free(struct sheafy_req *r) {
	void *obj;
	
	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES) 
		return -EINVAL;
	obj = handles[r->idx];
	if (!obj) 
		return -ENOENT;
	kmem_cache_free(sheafy_cache, obj); 

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
	default:           
		ret = -ENOTTY;      
		break;
	}
	mutex_unlock(&sheafy_lock);

	return ret;
}

static int sheafy_open(struct inode *i, struct file *f) { return 0; }

static int sheafy_release(struct inode *i, struct file *f){ return 0; }

static const struct file_operations sheafy_fops = {
	.owner=THIS_MODULE, .open=sheafy_open, .release=sheafy_release,
	.unlocked_ioctl=sheafy_ioctl, .compat_ioctl=sheafy_ioctl,
};

static char *sheafy_devnode(const struct device *dev, umode_t *mode) { 
	if (mode) 
		*mode = 0666; 

	return NULL; 
}

static int __init sheafy_init(void) {
	sheafy_cache = kmem_cache_create("sheafy_ctx", SHEAFY_OBJ_SZ, 0, SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT, NULL);
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
	sheafy_dev = device_create(sheafy_class, NULL, MKDEV(major,0), NULL, DEVICE_NAME);
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
	device_destroy(sheafy_class, MKDEV(major,0));
	class_destroy(sheafy_class);
	unregister_chrdev(major, DEVICE_NAME);
	kmem_cache_destroy(sheafy_cache);
}

module_init(sheafy_init);
module_exit(sheafy_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius (w1sdom) - bluedragonsec.com");
MODULE_DESCRIPTION("Vulnerable LKM: SLUB sheaves 7.0 - same cache UAF, cred_jar merge");
