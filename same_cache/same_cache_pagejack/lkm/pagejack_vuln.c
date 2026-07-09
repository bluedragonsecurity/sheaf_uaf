/*
 * linux kernel 7.0 same cache UAF exploitation p0c using pagejack + dirtycred
 * Antonius - bluedragonsec.om
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#define DEVICE_NAME  "pjvuln"
#define OBJ_SIZE     160
#define PJ_ALLOC     _IO('P', 1)
#define PJ_FREE      _IO('P', 2)
#define PJ_WRITE     _IOW('P', 3, struct pj_write_req)
struct pj_write_req {
    unsigned long offset;
    unsigned long length;
    void __user  *data;
};
static void *vuln_obj;
static int   obj_allocated;

static long pj_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    void *sacrificial;
    struct pj_write_req req;

    switch (cmd) {
    case PJ_ALLOC:
        if (obj_allocated) {
            pr_warn("pjvuln: slot occupied, free first\n");
            return -EBUSY;
        }
        vuln_obj = kmalloc(OBJ_SIZE, GFP_KERNEL_ACCOUNT);
        if (!vuln_obj)
            return -ENOMEM;
        obj_allocated = 1;
        return 0;
    case PJ_FREE: {
        if (!obj_allocated) {
            pr_warn("pjvuln: nothing to free\n");
            return -EINVAL;
        }
        sacrificial = kmalloc(OBJ_SIZE, GFP_KERNEL_ACCOUNT);
        if (!sacrificial) {
            pr_warn("pjvuln: sacrificial alloc failed\n");
            return -ENOMEM;
        }
        kfree(vuln_obj);    
        kfree(sacrificial);    
        obj_allocated = 0; 
        return 0;
    }
    case PJ_WRITE: {
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (req.offset >= OBJ_SIZE || req.length == 0)
            return -EINVAL;
        if (req.offset + req.length > OBJ_SIZE)
            return -EINVAL;
        if (!vuln_obj)
            return -EINVAL;
        if (copy_from_user((char *)vuln_obj + req.offset, req.data, req.length))
            return -EFAULT;
        return 0;
    }
    default:
        return -ENOTTY;
    }
}

static const struct file_operations pj_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = pj_ioctl,
};

static struct miscdevice pj_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &pj_fops,
    .mode  = 0666,
};

static int __init pj_init(void) {
    int ret;

    vuln_obj = NULL;
    obj_allocated = 0;
    ret = misc_register(&pj_dev);
    if (ret) {
        pr_err("pjvuln: failed to register misc device\n");
        return ret;
    }

    return 0;
}

static void __exit pj_exit(void) {
    misc_deregister(&pj_dev);
}

module_init(pj_init);
module_exit(pj_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius - bluedragonsec.com");
MODULE_DESCRIPTION(" Linux kernel 7.0 Same Cache UAF exploitation p0c using pagejack + dirtycred");
