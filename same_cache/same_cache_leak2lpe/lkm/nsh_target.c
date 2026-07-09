/*
 * nsh_target.c - UAF write lkm for kernel 7.0
 * Demonstrating lpe from a single uaf write
 * UAF write used for leak
 * UAF write used for lpe
 * Antonius - bluedragonsec.com 
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
#define NSH_DEVICE_NAME "nsh_target"
#define NSH_MAGIC 'N'
#define NSH_ALLOC _IO(NSH_MAGIC, 0x01)
#define NSH_FREE  _IO(NSH_MAGIC, 0x02)
#define NSH_WRITE _IOW(NSH_MAGIC, 0x03, struct nsh_io)
#define NSH_SYNC  _IO(NSH_MAGIC, 0x04)          
#define NSH_INFO  _IOR(NSH_MAGIC, 0x05, struct nsh_info)
#define SX_SIZE_OFF     32
#define VICTIM_DATALEN  984
#define SX_HDR          40
#define NSH_ALLOC_TOTAL (SX_HDR + VICTIM_DATALEN) /* 1024 -> cg-1k */
struct victim {
	unsigned long *wp;
	unsigned long  wv;
	unsigned char  pad[NSH_ALLOC_TOTAL - sizeof(unsigned long *) - sizeof(unsigned long)];
};
struct nsh_io   { __u32 off, len; __u8 buf[1024]; };
struct nsh_info { __u32 alloc_total; __u32 size_off; __u32 datalen; __u32 _pad; };
static DEFINE_MUTEX(nsh_lock);
static unsigned int alloc_total;
static struct victim *victim;
static bool freed;

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
		if (!victim) { 
			ret = -ENOMEM; 
			break; 
		}
		memset(victim, 0, alloc_total);
		victim->wp = &victim->wv;   
		victim->wv = 0;
		freed = false;
		pr_info("nsh: alloc victim=%px (kmalloc-cg-1k, total=%u)\n", victim, alloc_total);
		break;
	case NSH_FREE:
		if (!victim || freed) { 
			ret = -ENOENT; 
			break; 
		}
		kfree(victim);
		freed = true;  /* dangling */
		pr_info("nsh: FREE victim=%px (dangling)\n", victim);
		break;
	case NSH_WRITE: 
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
			ret = -EFAULT; 
			break;
		}
		if (kio->len > sizeof(kio->buf) ||
		    kio->off + kio->len > alloc_total) {
			ret = -EINVAL; break;
		}
		memcpy((char *)victim + kio->off, kio->buf, kio->len); /* UAF write */
		break;
	case NSH_SYNC: 
		if (!victim) { 
			ret = -ENOENT; 
			break; 
		}
		if (victim->wp)
			*(victim->wp) = victim->wv;
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
	alloc_total = NSH_ALLOC_TOTAL;
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
MODULE_AUTHOR("ev1lut10n / sw0rdm4n - bluedragonsecurity.com");
MODULE_DESCRIPTION("Single UAF write LKM - leak via xattr over read for linux 7.0");
