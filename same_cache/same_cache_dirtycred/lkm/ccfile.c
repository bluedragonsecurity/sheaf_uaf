/*
 * Vulnerable lkm for dirtycred same cache uaf
 * antonius - bluedragonsec.com 
 * linux kernel 7.0
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>
#define DEVICE_NAME      "ccfile"
#define CLASS_NAME       "ccfile"
#define CC_MAX_HANDLES   4096
#define PIN_PATH         "/dev/null"
struct cc_req {
   int idx;
   unsigned long off;
   __u64  val;
   int len;          
};
#define CC_IOC_MAGIC      'F'
#define CC_OPEN_PIN       _IOW (CC_IOC_MAGIC, 1, struct cc_req)
#define CC_BUG_FREE       _IOW (CC_IOC_MAGIC, 2, struct cc_req)
#define CC_UAF_WRITE      _IOW (CC_IOC_MAGIC, 3, struct cc_req)
static int                 major;
static struct class       *cc_class;
static struct device      *cc_dev;
static struct file       **handles;
static DEFINE_MUTEX(cc_lock);

static long do_open_pin(int idx) {
	struct file *f;

	if (idx < 0 || idx >= CC_MAX_HANDLES) 
	    return -EINVAL;
	if (handles[idx]) 
	    return -EEXIST;
	f = filp_open(PIN_PATH, O_RDWR, 0);
	if (IS_ERR(f)) 
		return PTR_ERR(f);
	handles[idx] = f;
	
	return 0;
}

static long do_bug_free(int idx) {
	struct file *f;

	if (idx < 0 || idx >= CC_MAX_HANDLES) 
		return -EINVAL;
	f = handles[idx];
	if (!f) 
		return -ENOENT;
	fput(f);
	
	return 0;
}

static long do_uaf_write(int idx, unsigned long off, __u64 val, int len) {
	struct file *f;
	void *target;

	if (idx < 0 || idx >= CC_MAX_HANDLES)     
	    return -EINVAL;
	if (len != 1 && len != 2 && len != 4 && len != 8) 
	    return -EINVAL;
	if (off + (unsigned long)len > 512)       
	    return -EINVAL;
	f = handles[idx];
	if (!f) 
	    return -ENOENT;
	target = (void *)f + off;
	switch (len) {
	    case 1: 
			*(__u8  *)target = (__u8 )val; 
			break;
	    case 2: 
			*(__u16 *)target = (__u16)val; 
			break;
	    case 4: 
			*(__u32 *)target = (__u32)val; 
			break;
	    case 8: 
			*(__u64 *)target = (__u64)val; 
			break;
	}
	
	return 0;
}

static long cc_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	struct cc_req r;
	long ret;

	if (copy_from_user(&r, (void __user *)arg, sizeof(r))) 
		return -EFAULT;
	mutex_lock(&cc_lock);
	switch (cmd) {
	    case CC_OPEN_PIN:  
	        ret = do_open_pin(r.idx); 
	        break;
	    case CC_BUG_FREE:  
	        ret = do_bug_free(r.idx); 
	        break;
	    case CC_UAF_WRITE: 
	        ret = do_uaf_write(r.idx, r.off, r.val, r.len); 
	        break;
	    default:           
	        ret = -ENOTTY;
	}
	mutex_unlock(&cc_lock);
	
	return ret;
}

static int cc_open(struct inode *i, struct file *f) { return 0; }

static int cc_release(struct inode *i, struct file *f) { return 0; }

static const struct file_operations cc_fops = {
	.owner          = THIS_MODULE,
	.open           = cc_open,
	.release        = cc_release,
	.unlocked_ioctl = cc_ioctl,
	.compat_ioctl   = cc_ioctl,
};

static char *cc_devnode(const struct device *dev, umode_t *mode) { 
    if (mode) 
		*mode = 0666; 
    
    return NULL; 
}

static int __init cc_init(void) {
	handles = vzalloc(sizeof(void *) * CC_MAX_HANDLES);
	if (!handles) 
	    return -ENOMEM;
	major = register_chrdev(0, DEVICE_NAME, &cc_fops);
	if (major < 0) { 
	    vfree(handles); 
	    return major; 
	}
	cc_class = class_create(CLASS_NAME);
	if (IS_ERR(cc_class)) { 
	    unregister_chrdev(major, DEVICE_NAME); 
	    vfree(handles); 
	    return PTR_ERR(cc_class); 
	}
	cc_class->devnode = cc_devnode;
	cc_dev = device_create(cc_class, NULL, MKDEV(major,0), NULL, DEVICE_NAME);
	if (IS_ERR(cc_dev)) { 
	    class_destroy(cc_class); 
	    unregister_chrdev(major, DEVICE_NAME); 
	    vfree(handles); 
	    return PTR_ERR(cc_dev); 
	}
		
	return 0;
}

static void __exit cc_exit(void) {
	device_destroy(cc_class, MKDEV(major,0));
	class_destroy(cc_class);
	unregister_chrdev(major, DEVICE_NAME);
	vfree(handles);
}

module_init(cc_init);
module_exit(cc_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius - bluedragonsec.com");
MODULE_DESCRIPTION("DirtyCred UAF write demo");
