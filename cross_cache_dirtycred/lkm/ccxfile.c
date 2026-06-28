/*
 * ccxfile.c - UAF vulnerable lkm ( for dirtycred demo on Linux 7.0)
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
#include <linux/printk.h>
#include <linux/vmalloc.h>
#define DEVICE_NAME "ccxfile"
#define CLASS_NAME "ccxfile"
#define CCX_MAX_SLOTS 8192 /* groom 4096 + spare  */
#define CCX_OBJ_SIZE 192    
struct ccx_req {
   int idx;
   unsigned long off;
   __u64 val;
   int len; 
};
#define CCX_IOC_MAGIC 'X'
#define CCX_ALLOC _IOWR(CCX_IOC_MAGIC, 1, struct ccx_req)
#define CCX_FREE _IOW (CCX_IOC_MAGIC, 2, struct ccx_req)
#define CCX_UAF_WRITE _IOW (CCX_IOC_MAGIC, 3, struct ccx_req)
#define CCX_SHRINK _IO  (CCX_IOC_MAGIC, 4) /* drain barn + sheaves + partials -> ret2buddy */
#define CCX_RESTORE _IOW (CCX_IOC_MAGIC, 5, struct ccx_req) 
static int major;
static struct class *ccx_class;
static struct device  *ccx_dev;
static void **handles;        
static struct kmem_cache *ccx_cache;      
static DEFINE_MUTEX(ccx_lock);
static u32 *saved_off4;    
static u8  *saved_valid;   

static long do_alloc(int idx) {
    void *p;
	
    if (idx < 0 || idx >= CCX_MAX_SLOTS) return -EINVAL;
    if (handles[idx]) return -EEXIST;
    p = kmem_cache_alloc(ccx_cache, GFP_KERNEL);
    if (!p) return -ENOMEM;
    memset(p, 0, CCX_OBJ_SIZE);
    handles[idx] = p;
	
    return 0;
}

static long do_free(int idx) {
    void *p;

    if (idx < 0 || idx >= CCX_MAX_SLOTS) 
        return -EINVAL;
    p = handles[idx];
    if (!p) 
        return -ENOENT;
    kmem_cache_free(ccx_cache, p);

    return 0;
}

static long do_uaf_write(int idx, unsigned long off, __u64 val, int len) {
    void *target;

    if (idx < 0 || idx >= CCX_MAX_SLOTS) 
        return -EINVAL;
    if (len != 1 && len != 2 && len != 4 && len != 8) 
        return -EINVAL;
    if (off + (unsigned long)len > CCX_OBJ_SIZE)      
        return -EINVAL;
    if (!handles[idx])                                
        return -ENOENT;
    target = handles[idx] + off;
    if (off == 4 && len == 4 && !saved_valid[idx]) {
        saved_off4[idx]  = READ_ONCE(*(u32 *)target);
	    saved_valid[idx] = 1;
    }
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

static long do_restore(int idx) {
    void *target;

    if (idx < 0 || idx >= CCX_MAX_SLOTS) 
        return -EINVAL;
    if (!handles[idx])                   
    	return -ENOENT;
    if (!saved_valid[idx])               
    	return 0;  
    target = handles[idx] + 4;
    WRITE_ONCE(*(u32 *)target, saved_off4[idx]);
    saved_valid[idx] = 0;
	
   return 0;
}

static long do_shrink(void) {
	int ret = kmem_cache_shrink(ccx_cache);
	
	return 0;
}

static long ccx_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct ccx_req r = {0};
    long ret;

    if (cmd != CCX_SHRINK &&  copy_from_user(&r, (void __user *)arg, sizeof(r)))
        return -EFAULT;
	mutex_lock(&ccx_lock);
    switch (cmd) {
	case CCX_ALLOC:      
	    ret = do_alloc(r.idx);                          
	    break;
	case CCX_FREE:       
	    ret = do_free(r.idx);                           
	    break;
	case CCX_UAF_WRITE:  
	    ret = do_uaf_write(r.idx, r.off, r.val, r.len); 
	    break;
	case CCX_SHRINK:     
	    ret = do_shrink();                              
	    break;
	case CCX_RESTORE:    
	    ret = do_restore(r.idx);                        
	    break;
	default:             
	    ret = -ENOTTY;                                  
	    break;
    }
    mutex_unlock(&ccx_lock);
	
    return ret;
}

static int ccx_open(struct inode *i, struct file *f) { return 0; }
static int ccx_release(struct inode *i, struct file *f) { return 0; }

static const struct file_operations ccx_fops = {
    .owner = THIS_MODULE,
    .open = ccx_open,
    .release = ccx_release,
    .unlocked_ioctl = ccx_ioctl,
    .compat_ioctl = ccx_ioctl,
};

static char *ccx_devnode(const struct device *dev, umode_t *mode) {
    if (mode) *mode = 0666;
        return NULL;
}

static int __init ccx_init(void) {
    int ret;

    handles = vzalloc(sizeof(void *) * CCX_MAX_SLOTS);
    if (!handles) 
        return -ENOMEM;
    saved_off4 = vzalloc(sizeof(u32) * CCX_MAX_SLOTS);
    if (!saved_off4) { 
        vfree(handles); 
        return -ENOMEM; 
    }
    saved_valid = vzalloc(sizeof(u8) * CCX_MAX_SLOTS);
    if (!saved_valid) { 
        vfree(saved_off4); 
        vfree(handles); 
        return -ENOMEM; 
    }
    ccx_cache = kmem_cache_create("ccxfile_a", CCX_OBJ_SIZE,0 , SLAB_HWCACHE_ALIGN | SLAB_NO_MERGE, NULL);
    if (!ccx_cache) {
        vfree(saved_valid); vfree(saved_off4); vfree(handles);
	    return -ENOMEM;
    }
    major = register_chrdev(0, DEVICE_NAME, &ccx_fops);
    if (major < 0) { 
        ret = major; 
        goto err_chrdev; 
    }
    ccx_class = class_create(CLASS_NAME);
    if (IS_ERR(ccx_class)) { 
        ret = PTR_ERR(ccx_class); 
        goto err_class; 
    }
    ccx_class->devnode = ccx_devnode;
    ccx_dev = device_create(ccx_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(ccx_dev)) { 
        ret = PTR_ERR(ccx_dev); 
        goto err_dev; 
    }
    pr_info("ccxfile  loaded");
    return 0;
err_dev:
    class_destroy(ccx_class);
err_class:
    unregister_chrdev(major, DEVICE_NAME);
err_chrdev:
    kmem_cache_destroy(ccx_cache);
    vfree(saved_valid);
    vfree(saved_off4);
    vfree(handles);
    
    return ret;
}

static void __exit ccx_exit(void) {
    int i;
	
    mutex_lock(&ccx_lock);
    for (i = 0; i < CCX_MAX_SLOTS; i++)
        handles[i] = NULL;
    mutex_unlock(&ccx_lock);
    device_destroy(ccx_class, MKDEV(major, 0));
    class_destroy(ccx_class);
    unregister_chrdev(major, DEVICE_NAME);
    kmem_cache_destroy(ccx_cache);
    vfree(saved_valid);
    vfree(saved_off4);
    vfree(handles);
    pr_info("ccxfile: unloaded\n");
}

module_init(ccx_init);
module_exit(ccx_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius (w1sdom / sw0rdm4n) - bluedragonsec.com");
MODULE_DESCRIPTION("Vulnerable LKM for cross cache UAF using DirtyCred - linux 7.0");
