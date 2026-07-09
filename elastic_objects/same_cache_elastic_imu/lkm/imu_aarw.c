/*
 * build AARW from UAF using io_mapped_ubuf
 * Antonius — bluedragonsec.com
 * Linux kernel 7.0, KASLR ON, kptr_restrict 2
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
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
extern struct kmem_cache *kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH + 1];
#define DEVNAME    "imu_aarw"
#define OBJ_SIZE   1024
#define MAX_SLOTS  256
#define SLAB_SHIFT 10
static int rnd_idx = 8;
module_param(rnd_idx, int, 0444);
MODULE_PARM_DESC(rnd_idx, "RANDOM_KMALLOC_CACHES index");
struct sa_req {
	int    slot;
	__u32  len;
	__u64  ubuf;
};
struct sa_kern_info {
	__u32  tasks_offset;
	__u32  pid_offset;
	__u32  cred_offset;
	__u32  comm_offset;
	__u32  uid_offset;
	__u32  id_count;          
	__u32  page_struct_size;  
	__u32  _pad;
};
#define SA_ALLOC        _IOWR('S', 0x01, struct sa_req)
#define SA_FREE         _IOWR('S', 0x02, struct sa_req)
#define SA_PEEK         _IOWR('S', 0x03, struct sa_req)
#define SA_POKE         _IOWR('S', 0x04, struct sa_req)
#define SA_KERN_INFO    _IOWR('S', 0x10, struct sa_kern_info)
#define SA_RESET        _IO('S', 0x30)
#define SA_SET_CACHE    _IOW('S', 0x31, int)
static int           major;
static struct class  *cls;
static DEFINE_MUTEX(lock);
static void          *slots[MAX_SLOTS];
static struct kmem_cache *target_cache;

static long dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	struct sa_req req;
	struct sa_kern_info ki;
	int ret = 0, i, idx;

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
		slots[req.slot] = kmem_cache_alloc(target_cache, GFP_KERNEL);
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
			ret = -EFAULT; break;
		}
		if (req.slot < 0 || req.slot >= MAX_SLOTS || !slots[req.slot]) {
			ret = -EINVAL; break;
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
		ki.tasks_offset     = offsetof(struct task_struct, tasks);
		ki.pid_offset       = offsetof(struct task_struct, pid);
		ki.cred_offset      = offsetof(struct task_struct, cred);
		ki.comm_offset      = offsetof(struct task_struct, comm);
		ki.uid_offset       = offsetof(struct cred, uid);
		ki.id_count         = 8;
		ki.page_struct_size = (u32)sizeof(struct page);
		if (copy_to_user((void __user *)arg, &ki, sizeof(ki)))
			ret = -EFAULT;
		break;
	case SA_RESET: {
		for (i = 0; i < MAX_SLOTS; i++)
			slots[i] = NULL;
		break;
	}
	case SA_SET_CACHE: {
		if (copy_from_user(&idx, (void __user *)arg, sizeof(idx))) {
			ret = -EFAULT; break;
		}
		if (idx < 0 || idx >= 16) {
			ret = -EINVAL; break;
		}
		target_cache = kmalloc_caches[idx][SLAB_SHIFT];
		if (!target_cache) {
			ret = -ENOENT; break;
		}
		rnd_idx = idx;
		break;
	}
	default:
		ret = -ENOTTY;
	}
	mutex_unlock(&lock);

	return ret;
}

static int dev_open(struct inode *i, struct file *f)  { return 0; }

static int dev_release(struct inode *i, struct file *f) { return 0; }

static struct file_operations fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = dev_ioctl,
	.open           = dev_open,
	.release        = dev_release,
};

static char *imu_devnode(const struct device *dev, umode_t *mode) {
	if (mode) 
		*mode = 0666;

	return NULL;
}

static int __init imu_aarw_init(void) {
	if (rnd_idx < 0 || rnd_idx >= 16)
		return -EINVAL;
	target_cache = kmalloc_caches[rnd_idx][SLAB_SHIFT];
	if (!target_cache)
		return -ENOENT;
	major = register_chrdev(0, DEVNAME, &fops);
	if (major < 0) 
		return major;
	cls = class_create(DEVNAME);
	cls->devnode = imu_devnode;
	device_create(cls, NULL, MKDEV(major, 0), NULL, DEVNAME);
	
	return 0;
}

static void __exit imu_aarw_exit(void) {
	int i;

	for (i = 0; i < MAX_SLOTS; i++) 
		slots[i] = NULL;
	device_destroy(cls, MKDEV(major, 0));
	class_destroy(cls);
	unregister_chrdev(major, DEVNAME);
}

module_init(imu_aarw_init);
module_exit(imu_aarw_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius - bluedragonsec.com");
MODULE_DESCRIPTION("build aarw using io_mapped_ubuf from uaf bug (kernel 7.0)");
