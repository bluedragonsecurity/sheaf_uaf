/*
 * vulner UAF lkm - linux 7.0
 * build AARW using io_mapped_ubuf 
 * ev1lut10n / sw0rdm4n
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/ioctl.h>
#include <linux/mm.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#define DEVNAME    "imu_aarw"
#define OBJ_SIZE   1024
#define MAX_SLOTS  8192
struct sa_req { int slot; __u32 len; __u64 ubuf; };
struct sa_kern_info {
	__u32 tasks_offset, pid_offset, cred_offset, comm_offset;
	__u32 uid_offset, id_count, page_struct_size, _pad;
};
#define SA_ALLOC     _IOWR('S', 0x01, struct sa_req)
#define SA_FREE      _IOWR('S', 0x02, struct sa_req)
#define SA_PEEK      _IOWR('S', 0x03, struct sa_req)
#define SA_POKE      _IOWR('S', 0x04, struct sa_req)
#define SA_KERN_INFO _IOWR('S', 0x10, struct sa_kern_info)
#define SA_RESET     _IO('S', 0x30)
static int major;
static struct class *cls;
static DEFINE_MUTEX(lock);
static void *slots[MAX_SLOTS];

static long dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	struct sa_req req;
	struct sa_kern_info ki;
	int ret = 0, i;

	mutex_lock(&lock);
	switch (cmd) {
	case SA_ALLOC:
		if (copy_from_user(&req, (void __user *)arg, sizeof(req))) { 
			ret = -EFAULT; 
			break; 
		}
		if (req.slot < 0 || req.slot >= MAX_SLOTS) { 
			ret = -EINVAL; 
			break; 
		}
		if (slots[req.slot]) { 
			ret = -EBUSY; 
			break; 
		}
		slots[req.slot] = kmalloc(OBJ_SIZE, GFP_KERNEL_ACCOUNT);
		if (!slots[req.slot]) { 
			ret = -ENOMEM; 
			break; 
		}
		memset(slots[req.slot], 'A', OBJ_SIZE);
		break;
	case SA_FREE:
		if (copy_from_user(&req, (void __user *)arg, sizeof(req))) { 
			ret = -EFAULT; 
			break; 
		}
		if (req.slot < 0 || req.slot >= MAX_SLOTS || !slots[req.slot]) { 
			ret = -EINVAL; 
			break; 
		}
		kfree(slots[req.slot]);
		break;
	case SA_PEEK:
		if (copy_from_user(&req, (void __user *)arg, sizeof(req))) { 
			ret = -EFAULT; 
			break; 
		}
		if (req.slot < 0 || req.slot >= MAX_SLOTS || !slots[req.slot]) { 
			ret = -EINVAL; 
			break; 
		}
		if (req.len > OBJ_SIZE) 
			req.len = OBJ_SIZE;
		if (copy_to_user((void __user *)req.ubuf, slots[req.slot], req.len))
			ret = -EFAULT;
		break;
	case SA_POKE:
		if (copy_from_user(&req, (void __user *)arg, sizeof(req))) { 
			ret = -EFAULT; 
			break; 
		}
		if (req.slot < 0 || req.slot >= MAX_SLOTS || !slots[req.slot]) { 
			ret = -EINVAL; 
			break; 
		}
		if (req.len > OBJ_SIZE) 
			req.len = OBJ_SIZE;
		if (copy_from_user(slots[req.slot], (void __user *)req.ubuf, req.len))
			ret = -EFAULT;
		break;
	case SA_KERN_INFO:
		memset(&ki, 0, sizeof(ki));
		ki.tasks_offset = offsetof(struct task_struct, tasks);
		ki.pid_offset = offsetof(struct task_struct, pid);
		ki.cred_offset = offsetof(struct task_struct, cred);
		ki.comm_offset = offsetof(struct task_struct, comm);
		ki.uid_offset = offsetof(struct cred, uid);
		ki.id_count = 8;
		ki.page_struct_size = sizeof(struct page);
		if (copy_to_user((void __user *)arg, &ki, sizeof(ki)))
			ret = -EFAULT;
		break;
	case SA_RESET: {
		for (i = 0; i < MAX_SLOTS; i++) 
			slots[i] = NULL;
		break;
	}
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
MODULE_AUTHOR("sw0rdm4n / ev1lut10n - bluedragonsec.com");
MODULE_DESCRIPTION("Cross-cache io_mapped_ubuf AARW (kmalloc GFP_KERNEL victim)");
