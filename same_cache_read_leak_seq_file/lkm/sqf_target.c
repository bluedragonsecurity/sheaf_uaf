/*
 * sqf_target.c - UAF read vulner LKM 
 * vehicle : struct seq_file (seq_file_cache, SLAB_ACCOUNT)
 * Antonius - bluedragonsec.com
 * linux kernel 7.0
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/ioctl.h>
#include <linux/seq_file.h>
#define SQF_DEVICE_NAME "sqf_target"
#define SQF_MAGIC  'Q'
#define SQF_ALLOC  _IO(SQF_MAGIC, 0x01)
#define SQF_FREE   _IO(SQF_MAGIC, 0x02)
#define SQF_READ   _IOR(SQF_MAGIC, 0x03, struct sqf_io)
#define SQF_INFO   _IOR(SQF_MAGIC, 0x05, struct sqf_info)
/* max copy 'len' byte from dangling to userland */
struct sqf_io   { __u32 off; __u32 len; __u8 buf[1024]; };
struct sqf_info { __u32 obj_size; __u32 _pad[3]; };
static DEFINE_MUTEX(sqf_lock);
static struct kmem_cache *sqf_cache;
static void *victim;
static bool  freed;
static unsigned int obj_size;

static long sqf_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	long ret = 0;
	struct sqf_io *kio = NULL;

	mutex_lock(&sqf_lock);
	switch (cmd) {
	case SQF_ALLOC:
		if (victim && !freed) { 
			ret = -EEXIST; 
			break; 
		}
		victim = kmem_cache_alloc(sqf_cache, GFP_KERNEL_ACCOUNT);
		if (!victim) { 
			ret = -ENOMEM; 
			break; 
		}
		memset(victim, 0, obj_size);
		freed = false;
		pr_info("sqf: ALLOC victim=%px (sqf_victim, size=%u)\n", victim, obj_size);
		break;
	case SQF_FREE:
		if (!victim || freed) { 
			ret = -ENOENT; 
			break; 
		}
		kmem_cache_free(sqf_cache, victim);
		freed = true;
		pr_info("sqf: free victim=%px (dangling)\n", victim);
		break;
	case SQF_READ: /* UAF read  */
		if (!victim) { 
			ret = -ENOENT; 
			break; 
		}
		kio = kmalloc(sizeof(*kio), GFP_KERNEL);
		if (!kio) { 
			ret = -ENOMEM; 
			break; 
		}
		if (copy_from_user(kio, (void __user *)arg, sizeof(*kio))) {
			ret = -EFAULT; break;
		}
		if (kio->len > sizeof(kio->buf)) { 
			ret = -EINVAL; 
			break; 
		}
		memcpy(kio->buf, (char *)victim + kio->off, kio->len);
		if (copy_to_user((void __user *)arg, kio, sizeof(*kio)))
			ret = -EFAULT;
		break;
	case SQF_INFO: {
		struct sqf_info info = { .obj_size = obj_size };
		if (copy_to_user((void __user *)arg, &info, sizeof(info)))
			ret = -EFAULT;
		break;
	}
	default:
		ret = -ENOTTY;
	}
	kfree(kio);
	mutex_unlock(&sqf_lock);

	return ret;
}

static const struct file_operations sqf_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = sqf_ioctl,
	.compat_ioctl   = sqf_ioctl,
};

static struct miscdevice sqf_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = SQF_DEVICE_NAME,
	.fops  = &sqf_fops,
	.mode  = 0666,
};

static int __init sqf_init(void) {
	/* dedicated cache, object_size = sizeof(struct seq_file) */
	obj_size = sizeof(struct seq_file);
	sqf_cache = kmem_cache_create("sqf_victim", obj_size, 0, SLAB_ACCOUNT, NULL);
	if (!sqf_cache)
		return -ENOMEM;
	if (misc_register(&sqf_dev)) {
		kmem_cache_destroy(sqf_cache);
		return -ENODEV;
	}
	
	return 0;
}

static void __exit sqf_exit(void) {
	misc_deregister(&sqf_dev);
	if (victim && !freed)
		kmem_cache_free(sqf_cache, victim);
	kmem_cache_destroy(sqf_cache);
}

module_init(sqf_init);
module_exit(sqf_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ev1lut10n - bluedragonsecurity.com");
MODULE_DESCRIPTION("Vulnerable LKM: single UAF read, cross-cache reclaim by seq_file, .text leak");
