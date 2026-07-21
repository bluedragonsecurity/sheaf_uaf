/*
 * SheavesSiphon Cross Cache -> pipe_buffer builds AARW 
 * linux 7.0 
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
#include <linux/ioctl.h>
struct pa_req { int slot; __u32 len; __u64 ubuf; };
#define DEVNAME "pipe_aarw"
#define OBJ_SIZE 1024
#define MAX_SLOTS 8192
#define PA_ALLOC _IOWR('P', 0x01, struct pa_req)
#define PA_FREE _IOWR('P', 0x02, struct pa_req)
#define PA_PEEK _IOWR('P', 0x03, struct pa_req)
#define PA_POKE _IOWR('P', 0x04, struct pa_req)
static void *slots[MAX_SLOTS];
static DEFINE_MUTEX(pa_lock);
static int pa_major;
static struct class *pa_class;
static struct device *pa_dev;

static long pa_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	struct pa_req req;
	long ret = 0;
	void *obj;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	if (req.slot < 0 || req.slot >= MAX_SLOTS)
		return -EINVAL;
	mutex_lock(&pa_lock);
	switch (cmd) {
	case PA_ALLOC: {
		obj = kmalloc(OBJ_SIZE, GFP_KERNEL);
		if (!obj) { 
			ret = -ENOMEM; 
			break; 
		}
		slots[req.slot] = obj;
		break;
	}
	case PA_FREE:
		if (!slots[req.slot]) { 
			ret = -ENOENT; 
			break; 
		}
		kfree(slots[req.slot]);
		break;
	case PA_PEEK:
		if (!slots[req.slot]) { 
			ret = -ENOENT; 
			break; 
		}
		if (req.len > OBJ_SIZE) { 
			ret = -EINVAL; 
			break; 
		}
		if (copy_to_user((void __user *)req.ubuf, slots[req.slot], req.len))
			ret = -EFAULT;
		break;
	case PA_POKE:
		if (!slots[req.slot]) { 
			ret = -ENOENT; 
			break; 
		}
		if (req.len > OBJ_SIZE) { 
			ret = -EINVAL; 
			break; 
		}
		if (copy_from_user(slots[req.slot], (void __user *)req.ubuf, req.len))
			ret = -EFAULT;
		break;
	default: 
		ret = -ENOTTY;
	}
	mutex_unlock(&pa_lock);

	return ret;
}

static const struct file_operations pa_fops = {
	.owner = THIS_MODULE, .unlocked_ioctl = pa_ioctl, .compat_ioctl = pa_ioctl,
};

static char *pa_devnode(const struct device *dev, umode_t *mode) { 
	if (mode) 
		*mode = 0666; 
		
	return NULL; 
}

static int __init pa_init(void) {
	pa_major = register_chrdev(0, DEVNAME, &pa_fops);
	if (pa_major < 0) 
		return pa_major;
	pa_class = class_create(DEVNAME);
	if (IS_ERR(pa_class)) { 
		unregister_chrdev(pa_major, DEVNAME); 
		return PTR_ERR(pa_class); 
	}
	pa_class->devnode = pa_devnode;
	pa_dev = device_create(pa_class, NULL, MKDEV(pa_major, 0), NULL, DEVNAME);

	return 0;
}

static void __exit pa_exit(void) {
	int i;

	device_destroy(pa_class, MKDEV(pa_major, 0));
	class_destroy(pa_class);
	unregister_chrdev(pa_major, DEVNAME);
	for (i = 0; i < MAX_SLOTS; i++) 
		slots[i] = NULL;
}
module_init(pa_init);
module_exit(pa_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius - bluedragonsec.com");
MODULE_DESCRIPTION("SheavesSiphon cross cache - pipe_buffer builds AARW");
