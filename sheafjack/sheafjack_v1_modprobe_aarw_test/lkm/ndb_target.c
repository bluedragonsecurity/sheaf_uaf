/*
 * SheafJack v1 Demo LKM - race to uaf - aarw
 * Antonius - www.bluedragonsec.com
 * for Linux 7.0 only
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/refcount.h>
#include <linux/list.h>
#define DEVICE_NAME      "ndb_target"
#define NDB_OBJ_SIZE     128
#define NDB_IOC_MAGIC    0xA4
#define NDB_BIND         _IOW(NDB_IOC_MAGIC, 1, struct ndb_io)
#define NDB_SCHEDULE     _IOW(NDB_IOC_MAGIC, 2, struct ndb_io)
#define NDB_READ         _IOWR(NDB_IOC_MAGIC, 3, struct ndb_io)
#define NDB_WRITE        _IOW(NDB_IOC_MAGIC, 4, struct ndb_io)
#define NDB_FLUSH        _IOW(NDB_IOC_MAGIC, 5, struct ndb_io)
struct ndb_io {
    u32  flags;                  
    u32  _pad0;
    u64  offset;               
    u64  length;
    u64  userptr;
};
struct ndb_session {
    struct list_head node;        
    refcount_t refs;       
    u32 seq;        
    u64 deadline;    
    char payload[96]; 
};
static_assert(sizeof(struct ndb_session) == NDB_OBJ_SIZE,"ndb_session must be exactly 128 bytes");
struct ndb_handle {
    struct ndb_session *sess;
    struct delayed_work timeout;
    bool                bound;
};
static struct kmem_cache  *ndb_cache;
static struct class       *ndb_class;
static struct device      *ndb_device;
static dev_t              ndb_dev;
static struct cdev        ndb_cdev;
static atomic_t           ndb_seq = ATOMIC_INIT(0);

static void ndb_timeout_fn(struct work_struct *w) {
    struct ndb_handle *h = container_of(to_delayed_work(w), struct ndb_handle, timeout);

    if (h->sess) {
        kmem_cache_free(ndb_cache, h->sess);
    }
    h->bound = false;
}

static int ndb_open(struct inode *i, struct file *f) {
    struct ndb_handle *h = kzalloc(sizeof(*h), GFP_KERNEL);

    if (!h)
        return -ENOMEM;
    INIT_DELAYED_WORK(&h->timeout, ndb_timeout_fn);
    f->private_data = h;

    return 0;
}

static int ndb_release(struct inode *i, struct file *f) {
    struct ndb_handle *h = f->private_data;

    if (h) {
        cancel_delayed_work_sync(&h->timeout);
        kfree(h);
    }

    return 0;
}

static long ndb_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct ndb_handle *h = f->private_data;
    struct ndb_io io;
    void __user *ubuf;

    if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
        return -EFAULT;
    ubuf = (void __user *)(uintptr_t)io.userptr;
    switch (cmd) {
    case NDB_BIND: {
        struct ndb_session *s;
        if (h->sess)
            return -EBUSY;
        s = kmem_cache_alloc(ndb_cache, GFP_KERNEL);
        if (!s)
            return -ENOMEM;
        INIT_LIST_HEAD(&s->node);         
        refcount_set(&s->refs, 1);
        s->seq = atomic_inc_return(&ndb_seq);
        s->deadline = jiffies + msecs_to_jiffies(io.flags);
        memset(s->payload, 0, sizeof(s->payload));
        if (io.length > sizeof(s->payload))
            io.length = sizeof(s->payload);
        if (io.length && copy_from_user(s->payload, ubuf, io.length)) {
            kmem_cache_free(ndb_cache, s);
            return -EFAULT;
        }
        h->sess = s;
        return 0;
    }
    case NDB_SCHEDULE:
        if (!h->sess || h->bound)
            return -EINVAL;
        h->bound = true;
        schedule_delayed_work(&h->timeout, msecs_to_jiffies(io.flags));
        return 0;
    case NDB_READ: {
        if (!h->sess)
            return -EINVAL;
        if (io.length > 4096)
            return -EINVAL;
        if (copy_to_user(ubuf, (char *)h->sess + io.offset, io.length))
            return -EFAULT;
        return 0;
    }
    case NDB_WRITE: {
        /* aarw at dangling pointer */
        if (!h->sess)
            return -EINVAL;
        if (io.length > 4096)
            return -EINVAL;
        if (copy_from_user((char *)h->sess + io.offset, ubuf, io.length))
            return -EFAULT;
        return 0;
    }
    case NDB_FLUSH: {
        /* trigger */
        struct ndb_session *s;
        s = kmem_cache_alloc(ndb_cache, GFP_KERNEL);
        if (!s)
            return -ENOMEM;
        if (io.length > sizeof(s->payload))
            io.length = sizeof(s->payload);
        if (io.length && copy_from_user(s, ubuf, io.length)) { /* do nothing */  }
        return 0;
    }
    default:
        return -ENOTTY;
    }
}

static const struct file_operations ndb_fops = {
    .owner          = THIS_MODULE,
    .open           = ndb_open,
    .release        = ndb_release,
    .unlocked_ioctl = ndb_ioctl,
};

static char *ndb_devnode(const struct device *d, umode_t *mode) {
    if (mode) 
        *mode = 0666;

    return NULL;
}

static int __init ndb_init(void) {
    int ret;

    ndb_cache = kmem_cache_create_usercopy("ndb_target",
                                           NDB_OBJ_SIZE, 0,
                                           SLAB_HWCACHE_ALIGN |
                                           SLAB_TYPESAFE_BY_RCU,
                                           0, NDB_OBJ_SIZE,
                                           NULL);
    if (!ndb_cache)
        return -ENOMEM;
    ret = alloc_chrdev_region(&ndb_dev, 0, 1, DEVICE_NAME);
    if (ret) 
        goto err_cache;
    cdev_init(&ndb_cdev, &ndb_fops);
    ret = cdev_add(&ndb_cdev, ndb_dev, 1);
    if (ret) 
        goto err_chr;
    ndb_class = class_create(DEVICE_NAME);
    if (IS_ERR(ndb_class)) { 
        ret = PTR_ERR(ndb_class); 
        goto err_cdev; 
    }
    ndb_class->devnode = ndb_devnode;
    ndb_device = device_create(ndb_class, NULL, ndb_dev, NULL, DEVICE_NAME);
    return 0;
err_cdev:  
    cdev_del(&ndb_cdev);
err_chr:   
    unregister_chrdev_region(ndb_dev, 1);
err_cache: 
    kmem_cache_destroy(ndb_cache);

    return ret;
}

static void __exit ndb_exit(void) {
    device_destroy(ndb_class, ndb_dev);
    class_destroy(ndb_class);
    cdev_del(&ndb_cdev);
    unregister_chrdev_region(ndb_dev, 1);
    kmem_cache_destroy(ndb_cache);
}

module_init(ndb_init);
module_exit(ndb_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius - bluedragonsec.com");
MODULE_DESCRIPTION("vulnerable race to UAF demo target for SheafJack v1");
