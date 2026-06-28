/*
 * sheaf_vuln.c - lkm with uaf for same cache reclaim
 * lpe via modprobe
 * Antonius - bluedragonsec.com
 * linux kernel 7.0
 * Communication path: generic netlink 
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/mutex.h>
#include <net/genetlink.h>
#include <net/sock.h>
#define SHEAFY_GENL_NAME     "sheafy"
#define SHEAFY_GENL_VERSION  1
#define SHEAFY_MAX_HANDLES   16
#define SHEAFY_DATA_LEN      216   /* object_size 256 (cap=28) */
struct sheafy_obj {
	int  (*log_fn)(const char *fmt, ...);
	unsigned long *wp;
	unsigned long  wv;
	unsigned long  cookie;
	unsigned long  len;
	unsigned char  data[SHEAFY_DATA_LEN];
};
struct sheafy_req {
	__s32 idx;
	__u32 _pad;
	__u64 cookie;
	__u64 len;
	__u64 ubuf;    
};
/* genl commands - 1:1 with the old ioctl ops */
enum {
	SHEAFY_CMD_UNSPEC = 0,
	SHEAFY_CMD_ALLOC,
	SHEAFY_CMD_WRITE,
	SHEAFY_CMD_READ,
	SHEAFY_CMD_FREE,
	SHEAFY_CMD_SYNC,
	__SHEAFY_CMD_MAX,
};
#define SHEAFY_CMD_MAX (__SHEAFY_CMD_MAX - 1)
/* netlink attributes */
enum {
	SHEAFY_ATTR_UNSPEC = 0,
	SHEAFY_ATTR_REQ,    
	SHEAFY_ATTR_DATA,   
	__SHEAFY_ATTR_MAX,
};
#define SHEAFY_ATTR_MAX (__SHEAFY_ATTR_MAX - 1)
static struct kmem_cache *sheafy_cache;
static struct sheafy_obj *handles[SHEAFY_MAX_HANDLES];
static DEFINE_MUTEX(sheafy_lock);

static const struct nla_policy sheafy_policy[SHEAFY_ATTR_MAX + 1] = {
	[SHEAFY_ATTR_REQ]  = { .type = NLA_BINARY,
			       .len = sizeof(struct sheafy_req) },
	[SHEAFY_ATTR_DATA] = { .type = NLA_BINARY },
};

static int get_req(struct genl_info *info, struct sheafy_req *out) {
	struct nlattr *na = info->attrs[SHEAFY_ATTR_REQ];

	if (!na || nla_len(na) < (int)sizeof(*out))
		return -EINVAL;
	memcpy(out, nla_data(na), sizeof(*out));
	
	return 0;
}

static long do_alloc(struct sheafy_req *r) {
	struct sheafy_obj *obj;

	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES)
		return -EINVAL;
	obj = kmem_cache_alloc(sheafy_cache, GFP_KERNEL);
	if (!obj)
		return -ENOMEM;
	obj->log_fn = _printk;
	obj->wp = &obj->wv;
	obj->wv  = 0;
	obj->cookie = r->cookie;
	obj->len = 0;
	handles[r->idx] = obj;
	pr_info("sheafy: alloc idx=%d obj=%px log_fn=%px\n", r->idx, obj, obj->log_fn);

	return 0;
}

static long do_write(struct sheafy_req *r) {
	struct sheafy_obj *obj;
	unsigned char kbuf[sizeof(struct sheafy_obj)];
	unsigned long n;

	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES)
		return -EINVAL;
	obj = handles[r->idx];   /* dangling */
	if (!obj)
		return -ENOENT;
	n = r->len;
	if (n > sizeof(struct sheafy_obj))
		n = sizeof(struct sheafy_obj);
	if (copy_from_user(kbuf, (void __user *)(unsigned long)r->ubuf, n))
		return -EFAULT;
	memcpy(obj, kbuf, n);    /* uaf write */

	return 0;
}

/*
 * do_read - info leak
 */
static long do_read(struct sheafy_req *r, struct genl_info *info) {
	struct sheafy_obj *obj;
	unsigned char kbuf[sizeof(struct sheafy_obj)];
	unsigned long n;
	struct sk_buff *msg;
	void *hdr;
	int rc;

	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES)
		return -EINVAL;
	obj = handles[r->idx];  
	if (!obj)
		return -ENOENT;
	n = r->len;
	if (n > sizeof(struct sheafy_obj))
		n = sizeof(struct sheafy_obj);
	memcpy(kbuf, obj, n);   
	pr_info("sheafy: READ  idx=%d obj=%px q0=%px n=%lu\n", r->idx, obj, *(void**)kbuf, n);
	msg = genlmsg_new(nla_total_size(n) + 64, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;
	hdr = genlmsg_put_reply(msg, info, info->family, 0, SHEAFY_CMD_READ);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}
	if (nla_put(msg, SHEAFY_ATTR_DATA, n, kbuf)) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return -EMSGSIZE;
	}
	genlmsg_end(msg, hdr);
	rc = genlmsg_reply(msg, info);

	return rc;
}

static long do_free(struct sheafy_req *r) {
	struct sheafy_obj *obj;

	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES)
		return -EINVAL;
	obj = handles[r->idx];
	if (!obj)
		return -ENOENT;
	pr_info("sheafy: FREE  idx=%d obj=%px\n", r->idx, obj);
	kmem_cache_free(sheafy_cache, obj);

	return 0;
}

/* uaf write */
static long do_sync(struct sheafy_req *r) {
	struct sheafy_obj *obj;

	if (r->idx < 0 || r->idx >= SHEAFY_MAX_HANDLES)
		return -EINVAL;
	obj = handles[r->idx];   /* dangling */
	if (!obj)
		return -ENOENT;
	if (obj->wp)
		*(obj->wp) = obj->wv;

	return 0;
}

/* genl command handlers  */
static int sheafy_c_alloc(struct sk_buff *skb, struct genl_info *info) {
	struct sheafy_req r; 
	long ret;
	
	if (get_req(info, &r)) 
		return -EINVAL;
	mutex_lock(&sheafy_lock); 
	ret = do_alloc(&r); 
	mutex_unlock(&sheafy_lock);

	return (int)ret;
}

static int sheafy_c_write(struct sk_buff *skb, struct genl_info *info) {
	struct sheafy_req r; 
	long ret;

	if (get_req(info, &r)) 
		return -EINVAL;
	mutex_lock(&sheafy_lock); 
	ret = do_write(&r); 
	mutex_unlock(&sheafy_lock);

	return (int)ret;
}

static int sheafy_c_read(struct sk_buff *skb, struct genl_info *info) {
	struct sheafy_req r; 
	long ret;

	if (get_req(info, &r)) 
		return -EINVAL;
	mutex_lock(&sheafy_lock); 
	ret = do_read(&r, info); 
	mutex_unlock(&sheafy_lock);

	return (int)ret;
}

static int sheafy_c_free(struct sk_buff *skb, struct genl_info *info) {
	struct sheafy_req r; 
	long ret;
	
	if (get_req(info, &r)) 
		return -EINVAL;
	mutex_lock(&sheafy_lock); 
	ret = do_free(&r); 
	mutex_unlock(&sheafy_lock);

	return (int)ret;
}
static int sheafy_c_sync(struct sk_buff *skb, struct genl_info *info) {
	struct sheafy_req r; 
	long ret;
	
	if (get_req(info, &r)) 
		return -EINVAL;
	mutex_lock(&sheafy_lock); 
	ret = do_sync(&r); 
	mutex_unlock(&sheafy_lock);

	return (int)ret;
}

static const struct genl_ops sheafy_ops[] = {
	{ .cmd = SHEAFY_CMD_ALLOC, .doit = sheafy_c_alloc },
	{ .cmd = SHEAFY_CMD_WRITE, .doit = sheafy_c_write },
	{ .cmd = SHEAFY_CMD_READ,  .doit = sheafy_c_read  },
	{ .cmd = SHEAFY_CMD_FREE,  .doit = sheafy_c_free  },
	{ .cmd = SHEAFY_CMD_SYNC,  .doit = sheafy_c_sync  },
};

static struct genl_family sheafy_family = {
	.name     = SHEAFY_GENL_NAME,
	.version  = SHEAFY_GENL_VERSION,
	.maxattr  = SHEAFY_ATTR_MAX,
	.policy   = sheafy_policy,
	.ops      = sheafy_ops,
	.n_ops    = ARRAY_SIZE(sheafy_ops),
	.module   = THIS_MODULE,
};

static int __init sheafy_init(void) {
	int rc;

	/* dedicated cache (NO SLAB_TYPESAFE_BY_RCU) */
	sheafy_cache = kmem_cache_create("sheafy_ctx", sizeof(struct sheafy_obj), 0, 0, NULL);
	if (!sheafy_cache)
		return -ENOMEM;
	rc = genl_register_family(&sheafy_family);
	if (rc) {
		kmem_cache_destroy(sheafy_cache);
		return rc;
	}
	
	return 0;
}

static void __exit sheafy_exit(void) {
	int i;

	mutex_lock(&sheafy_lock);
	for (i = 0; i < SHEAFY_MAX_HANDLES; i++)
		handles[i] = NULL;
	mutex_unlock(&sheafy_lock);
	genl_unregister_family(&sheafy_family);
	kmem_cache_destroy(sheafy_cache);
}

module_init(sheafy_init);
module_exit(sheafy_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("sw0rdm4n - bluedragonsec.com");
MODULE_DESCRIPTION("Vulnerable LKM - same cache UAF (genetlink transport) - kernel 7.0");
