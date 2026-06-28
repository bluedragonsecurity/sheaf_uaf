/*
 * ndb_leak.c - lkm with uaf write for information leak
 * same cache reclaim - info leak
 * for information leak only - no lpe
 * Antonius - bluedragonsec.com
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/miscdevice.h>
#include <linux/key.h>
#include <keys/user-type.h>
#define NDB_NAME   "ndb_leak"
#define NDB_MAGIC  'N'
#define NDB_BIND   _IOW(NDB_MAGIC, 1, struct ndb_bind_arg)
#define NDB_WRITE  _IOW(NDB_MAGIC, 3, struct ndb_write_arg)
#define NDB_INFO   _IOR(NDB_MAGIC, 4, struct ndb_info_arg)
#define NDB_UNBIND _IO(NDB_MAGIC, 5)
#define DATALEN_OFFSET 0x10
struct ndb_bind_arg  { __s32 key_serial; };
struct ndb_write_arg { __u16 datalen_value; };
struct ndb_info_arg  { __u64 obj_kva; };
static void           *g_payload;    /* dangling ptr to a user_key_payload  */
static DEFINE_MUTEX(g_lock);

static long do_bind(struct ndb_bind_arg __user *uarg) {
	struct ndb_bind_arg karg;
	key_ref_t kref;
	struct key *key;
	void *payload;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;
	kref = lookup_user_key(karg.key_serial, 0, KEY_NEED_READ);
	if (IS_ERR(kref))
		return PTR_ERR(kref);
	key = key_ref_to_ptr(kref);
	down_read(&key->sem);
	payload = dereference_key_locked(key);   
	up_read(&key->sem);
	mutex_lock(&g_lock);
	g_payload = payload;
	mutex_unlock(&g_lock);
	key_ref_put(kref);
	pr_info("ndb_leak: bound payload kva=%px (serial=%d)\n", payload, karg.key_serial);

	return 0;
}

static long do_write(struct ndb_write_arg __user *uarg) {
	struct ndb_write_arg karg;
	u8 *slot;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;
	mutex_lock(&g_lock);
	if (!g_payload) { 
		mutex_unlock(&g_lock); 
		return -ENOENT; 
	}
	/* UAF write : 2 bytes at payload+0x10 (user_key_payload.datalen). */
	slot = (u8 *)g_payload;
	*(u16 *)(slot + DATALEN_OFFSET) = karg.datalen_value;
	pr_info("ndb_leak: UAF write datalen=%u at kva=%px+0x%x\n", karg.datalen_value, g_payload, DATALEN_OFFSET);
	mutex_unlock(&g_lock);

	return 0;
}

static long do_info(struct ndb_info_arg __user *uarg) {
	struct ndb_info_arg karg;

	mutex_lock(&g_lock);
	karg.obj_kva = (u64)(uintptr_t)g_payload;
	mutex_unlock(&g_lock);
	if (copy_to_user(uarg, &karg, sizeof(karg)))
		return -EFAULT;

	return 0;
}

static long do_unbind(void) {
	mutex_lock(&g_lock);
	g_payload = NULL;
	mutex_unlock(&g_lock);

	return 0;
}

static long ndb_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	switch (cmd) {
	case NDB_BIND:   
		return do_bind((struct ndb_bind_arg __user *)arg);
	case NDB_WRITE:  
		return do_write((struct ndb_write_arg __user *)arg);
	case NDB_INFO:   
		return do_info((struct ndb_info_arg __user *)arg);
	case NDB_UNBIND: 
		return do_unbind();
	default:         
		return -ENOTTY;
	}
}

static const struct file_operations ndb_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = ndb_ioctl,
	.compat_ioctl   = ndb_ioctl,
};

static struct miscdevice ndb_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = NDB_NAME,
	.fops  = &ndb_fops,
	.mode  = 0666,
};

static int __init ndb_init(void) {
	int ret = misc_register(&ndb_dev);
	if (ret)
		return ret;
	
	return 0;
}

static void __exit ndb_exit(void) {
	misc_deregister(&ndb_dev);
}

module_init(ndb_init);
module_exit(ndb_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius - Blue Dragon Security");
MODULE_DESCRIPTION("UAF write LKM  - info leak via uaf write - vehicle : user_key_payload");
