/*
 * cross cache using SheavesSiphon -> io_uring reclaim -> build aarw with io_mapped_ubuf 
 * vulnerable UAF lkm for linux 7.0
 * Antonius - bluedragonsec.com
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/ioctl.h>
#define DEVNAME "imu_aarw"
#define OBJ_SIZE 1024
#define MAX_SLOTS 8192
struct sa_req { int slot; __u32 len; __u64 ubuf; };
#define SA_ALLOC _IOWR('S', 0x01, struct sa_req)
#define SA_FREE _IOWR('S', 0x02, struct sa_req)
#define SA_PEEK _IOWR('S', 0x03, struct sa_req)
#define SA_POKE _IOWR('S', 0x04, struct sa_req)
static int major;
static struct class *cls;
static DEFINE_MUTEX(lock);
static void *slots[MAX_SLOTS];

static long dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	struct sa_req req;
	int ret = 0;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.slot < 0 || req.slot >= MAX_SLOTS)
		return -EINVAL;
	mutex_lock(&lock);
	switch (cmd) {
	case SA_ALLOC:
		slots[req.slot] = kmalloc(OBJ_SIZE, GFP_KERNEL_ACCOUNT);
		if (!slots[req.slot]) { 
			ret = -ENOMEM; 
			break; 
		}
		memset(slots[req.slot], 'A', OBJ_SIZE);
		break;
	case SA_FREE:
		if (!slots[req.slot]) { 
			ret = -EINVAL; 
			break; 
		}
		kfree(slots[req.slot]);
		break;
	case SA_PEEK:
		if (!slots[req.slot]) { 
			ret = -EINVAL; 
			break; 
		}
		if (req.len > OBJ_SIZE) 
			req.len = OBJ_SIZE;
		if (copy_to_user((void __user *)req.ubuf, slots[req.slot], req.len))
			ret = -EFAULT;
		break;
	case SA_POKE:
		if (!slots[req.slot]) { 
			ret = -EINVAL; 
			break; 
		}
		if (req.len > OBJ_SIZE) 
			req.len = OBJ_SIZE;
		if (copy_from_user(slots[req.slot], (void __user *)req.ubuf, req.len))
			ret = -EFAULT;
		break;
	default:
		ret = -ENOTTY;
	}
	mutex_unlock(&lock);

	return ret;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = dev_ioctl,
};

static char *imu_devnode(const struct device *dev, umode_t *mode) {
	if (mode) 
		*mode = 0666;
	
	return NULL;
}

static int __init imu_init(void) {
	major = register_chrdev(0, DEVNAME, &fops);
	if (major < 0) 
		return major;
	cls = class_create(DEVNAME);
	cls->devnode = imu_devnode;
	device_create(cls, NULL, MKDEV(major, 0), NULL, DEVNAME);

	return 0;
}

static void __exit imu_exit(void) {
	int i;

	for (i = 0; i < MAX_SLOTS; i++) 
		slots[i] = NULL;
	device_destroy(cls, MKDEV(major, 0));
	class_destroy(cls);
	unregister_chrdev(major, DEVNAME);
}

module_init(imu_init);
module_exit(imu_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius - bluedragonsec.com");
MODULE_DESCRIPTION("SheavesSiphon cross cache io_mapped_ubuf AARW");
