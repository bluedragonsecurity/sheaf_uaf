/*
 * race to double free at vmsg_ioctl caused dangling pointer for aarw 
 * SheafJack v1 p0c for linux 7.0
 * Antonius - bluedragonsec.com
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/refcount.h>
#include <linux/list.h>
#define DEVICE_NAME      "vmsg"
#define VMSG_OBJ_SIZE    256
#define VMSG_TBL_SIZE    64
#define VMSG_IOC_MAGIC   0xB7
#define VMSG_BIND       _IOW(VMSG_IOC_MAGIC, 1, struct vmsg_io)
#define VMSG_FREE       _IOW(VMSG_IOC_MAGIC, 2, struct vmsg_io)
#define VMSG_READ       _IOWR(VMSG_IOC_MAGIC, 3, struct vmsg_io)
#define VMSG_WRITE      _IOW(VMSG_IOC_MAGIC, 4, struct vmsg_io)
#define VMSG_FLUSH      _IOW(VMSG_IOC_MAGIC, 5, struct vmsg_io)
struct vmsg_io {
    __u32 id;               
    __u32 _pad;
    __u64 offset; /* READ/WRITE - UNCHECKED */
    __u64 length;
    __u64 userptr;
};
struct vmsg {
    struct list_head node;       
    refcount_t       refs;        
    int              active;     
    u32              seq;        
    u32              _pad0;      
    u64              owner;      
    char             payload[216];
};
static_assert(sizeof(struct vmsg) == VMSG_OBJ_SIZE, "struct vmsg must be exactly 256 bytes");
static struct kmem_cache  *vmsg_cache;
static struct class       *vmsg_class;
static struct device      *vmsg_device;
static dev_t              vmsg_dev;
static struct cdev        vmsg_cdev;
static atomic_t           vmsg_seq = ATOMIC_INIT(0);
static struct vmsg *msg_tbl[VMSG_TBL_SIZE];

static int vmsg_open(struct inode *i, struct file *f) {
    return 0;
}

static int vmsg_release(struct inode *i, struct file *f) {
    return 0;
}

static long vmsg_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct vmsg_io  io;
    struct vmsg *m;
    void __user *ubuf;
    u32 idx;

    if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
        return -EFAULT;
    idx  = io.id & (VMSG_TBL_SIZE - 1);
    ubuf = (void __user *)(uintptr_t)io.userptr;
    switch (cmd) {
    case VMSG_BIND: {
        m = kmem_cache_alloc(vmsg_cache, GFP_KERNEL);
        if (!m)
            return -ENOMEM;
        INIT_LIST_HEAD(&m->node);            
        refcount_set(&m->refs, 1);
        m->active = 1;
        m->seq    = atomic_inc_return(&vmsg_seq);
        m->owner  = (u64)(uintptr_t)current;
        memset(m->payload, 0, sizeof(m->payload));
        if (io.length > sizeof(m->payload))
            io.length = sizeof(m->payload);
        if (io.length && copy_from_user(m->payload, ubuf, io.length)) {
            kmem_cache_free(vmsg_cache, m);
            return -EFAULT;
        }
        smp_wmb();
        WRITE_ONCE(msg_tbl[idx], m);

        return 0;
    }

    case VMSG_FREE: {
        /* TOCTOU race to DF - CVE-2017-2671 pattern */
        m = READ_ONCE(msg_tbl[idx]);
        if (!m)
            return -ENOENT;
        if (!READ_ONCE(m->active))
            return -EINVAL;
        WRITE_ONCE(m->active, 0);
        kmem_cache_free(vmsg_cache, m);

        return 0;
    }

    case VMSG_READ: {
        m = READ_ONCE(msg_tbl[idx]);
        if (!m)
            return -EINVAL;
        if (io.length > 4096)
            return -EINVAL;
        if (copy_to_user(ubuf, (char *)m + io.offset, io.length))
            return -EFAULT;
        return 0;
    }
    case VMSG_WRITE: {
        /* arbitrary write after dangling */
        m = READ_ONCE(msg_tbl[idx]);
        if (!m)
            return -EINVAL;
        if (io.length > 4096)
            return -EINVAL;
        if (copy_from_user((char *)m + io.offset, ubuf, io.length))
            return -EFAULT;
        return 0;
    }
    case VMSG_FLUSH: {
        struct vmsg *s = kmem_cache_alloc(vmsg_cache, GFP_KERNEL);
        if (!s)
            return -ENOMEM;
        if (io.length > sizeof(s->payload))
            io.length = sizeof(s->payload);
        if (io.length && copy_from_user(s, ubuf, io.length)) { /* do nothing  */ }
        return 0;
    }
    default:
        return -ENOTTY;
    }
}

static const struct file_operations vmsg_fops = {
    .owner          = THIS_MODULE,
    .open           = vmsg_open,
    .release        = vmsg_release,
    .unlocked_ioctl = vmsg_ioctl,
};

static char *vmsg_devnode(const struct device *d, umode_t *mode) {
    if (mode) 
        *mode = 0666;

    return NULL;
}

static int __init vmsg_init(void) {
    int ret;

    vmsg_cache = kmem_cache_create_usercopy("vmsg",
                                            VMSG_OBJ_SIZE, 0,
                                            SLAB_HWCACHE_ALIGN |
                                            SLAB_TYPESAFE_BY_RCU,
                                            0, VMSG_OBJ_SIZE,
                                            NULL);
    if (!vmsg_cache)
        return -ENOMEM;
    ret = alloc_chrdev_region(&vmsg_dev, 0, 1, DEVICE_NAME);
    if (ret) 
        goto err_cache;
    cdev_init(&vmsg_cdev, &vmsg_fops);
    ret = cdev_add(&vmsg_cdev, vmsg_dev, 1);
    if (ret) 
        goto err_chr;
    vmsg_class = class_create(DEVICE_NAME);
    if (IS_ERR(vmsg_class)) { 
        ret = PTR_ERR(vmsg_class); 
        goto err_cdev; 
    }
    vmsg_class->devnode = vmsg_devnode;
    vmsg_device = device_create(vmsg_class, NULL, vmsg_dev, NULL, DEVICE_NAME);
    return 0;
err_cdev:  
    cdev_del(&vmsg_cdev);
err_chr:   
    unregister_chrdev_region(vmsg_dev, 1);
err_cache: 
    kmem_cache_destroy(vmsg_cache);

    return ret;
}

static void __exit vmsg_exit(void) {
    device_destroy(vmsg_class, vmsg_dev);
    class_destroy(vmsg_class);
    cdev_del(&vmsg_cdev);
    unregister_chrdev_region(vmsg_dev, 1);
    kmem_cache_destroy(vmsg_cache);
}

module_init(vmsg_init);
module_exit(vmsg_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius - Blue Dragon Security");
MODULE_DESCRIPTION("SheafJack v1 p0c - race to DF -> aarw");
