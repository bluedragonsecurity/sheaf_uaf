/*
 * ndb_leak.c - lkm with uaf write for information leak
 * same cache reclaim - info leak
 * for information leak only - no lpe
 * Antonius - bluedragonsec.com
 * - alloc victim (kmalloc-cg-n) then free (dangling)
 * - setxattr user.* : simple_xattr_alloc reclaim slot victim.
 * - uaf write : overwrite 'size' (offset +32) 
 * - getxattr : memcpy(buffer, value, size) oob over read
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
#include <asm/pgtable_64_types.h>
#define NSH_DEVICE_NAME "nsh_target"
#define NSH_MAGIC  'N'
#define NSH_ALLOC  _IO(NSH_MAGIC, 0x01)
#define NSH_FREE   _IO(NSH_MAGIC, 0x02)
#define NSH_WRITE  _IOW(NSH_MAGIC, 0x03, struct nsh_io)
#define NSH_INFO   _IOR(NSH_MAGIC, 0x05, struct nsh_info)
#define SX_HDR      40
#define SX_SIZE_OFF 32  
#define VICTIM_DATALEN 24
struct nsh_io   { __u32 off, len; __u8 buf[512]; };
struct nsh_info { __u32 alloc_total; __u32 size_off; __u32 datalen; __u32 _pad; };
static DEFINE_MUTEX(nsh_lock);
static unsigned int alloc_total;
static void *victim;
static bool  freed;

static long nsh_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	long ret = 0;
	struct nsh_io *kio = NULL;

	mutex_lock(&nsh_lock);
	switch (cmd) {
	case NSH_ALLOC:
		if (victim && !freed) { 
			ret = -EEXIST; 
			break; 
		}
		victim = kmalloc(alloc_total, GFP_KERNEL_ACCOUNT);
		if (!victim) { ret = -ENOMEM; break; }
		memset(victim, 0, alloc_total);
		freed = false;
		break;
	case NSH_FREE:
		if (!victim || freed) { 
			ret = -ENOENT; 
			break; 
		}
		kfree(victim);
		freed = true;
		break;
	case NSH_WRITE: /* uaf write */
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
		if (kio->len > sizeof(kio->buf) ||
		    kio->off + kio->len > alloc_total) {
			ret = -EINVAL; break;
		}
		/* write via dangling - UAF write */
		memcpy((char *)victim + kio->off, kio->buf, kio->len);
		break;
	case NSH_INFO: {
		struct nsh_info info = {
			.alloc_total = alloc_total,
			.size_off    = SX_SIZE_OFF,
			.datalen     = VICTIM_DATALEN,
		};
		if (copy_to_user((void __user *)arg, &info, sizeof(info)))
			ret = -EFAULT;
		break;
	}
	default:
		ret = -ENOTTY;
	}

	kfree(kio);
	mutex_unlock(&nsh_lock);

	return ret;
}

static const struct file_operations nsh_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = nsh_ioctl,
	.compat_ioctl   = nsh_ioctl,
};

static struct miscdevice nsh_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = NSH_DEVICE_NAME,
	.fops  = &nsh_fops,
	.mode  = 0666,
};

static int __init nsh_init(void) {
	alloc_total = SX_HDR + VICTIM_DATALEN;
	if (misc_register(&nsh_dev))
		return -ENODEV;
	
	return 0;
}

static void __exit nsh_exit(void) {
	misc_deregister(&nsh_dev);
	if (victim && !freed)
		kfree(victim);
}

module_init(nsh_init);
module_exit(nsh_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ev1lut10n - bluedragonsecurity.com");
MODULE_DESCRIPTION("LKM with single UAF write for info leak, vehicle : simple_xattr, same cache kmalloc-cg");
