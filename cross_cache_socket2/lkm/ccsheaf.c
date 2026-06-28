/*
 * UAF vulnerable LKM for cross cache experiment on kernel 7.0
 * ret2buddy mechanics : 
 * drain sheaf main, spare, saturate barn, discard_slab() -> buddy
 * by: Antonius (sw0rdm4n) - bluedragonsec.com
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockptr.h>
#include <net/sock.h>
#define AF_CCS   45          
#define PF_CCS   AF_CCS
#define SOL_CCS  0x9100       
#define CCS_O_ALLOC      1    /* GFP_KERNEL - kmalloc-rnd-512 */
#define CCS_O_ALLOC_CG   2    /* GFP_KERNEL_ACCOUNT - kmalloc-cg-512 */
#define CCS_O_FREE       3   
#define CCS_O_PEEK       4    
#define CCS_O_POKE       5   
#define CCS_O_SYNC       6   
#define CCS_MAX_SLOTS    8192    
#define CCS_OBJ_SIZE     512    
typedef void (*ccs_complete_fn)(void *ctx);
struct ccs_object {
	ccs_complete_fn complete;  
	void           *ctx;       
	unsigned long  *wp;        
	unsigned long   wv;        
	u32             seq;       
	u32             _pad;      
	unsigned char   data[CCS_OBJ_SIZE - 0x28];
};
struct ccs_req {
	int           slot;
	unsigned long cookie;
	unsigned long len;
	unsigned long _resv;  
};
static struct ccs_object *slots[CCS_MAX_SLOTS];
static DEFINE_MUTEX(ccs_lock);

static long do_alloc(struct ccs_req *r, gfp_t gfp) {
	struct ccs_object *obj;

	if (r->slot < 0 || r->slot >= CCS_MAX_SLOTS)
		return -EINVAL;
	obj = kmalloc(sizeof(*obj), gfp);
	if (!obj)
		return -ENOMEM;
	obj->complete = (ccs_complete_fn)kfree; 
	obj->ctx      = NULL;
	obj->wp       = &obj->wv;              
	obj->wv       = 0;
	obj->seq      = (u32)r->cookie;
	obj->_pad     = 0;
	slots[r->slot] = obj;

	return 0;
}

static long do_free(struct ccs_req *r) {
	if (r->slot < 0 || r->slot >= CCS_MAX_SLOTS)
		return -EINVAL;
	if (!slots[r->slot])
		return -ENOENT;
	kfree(slots[r->slot]);

	return 0;
}

static long do_poke(struct ccs_req *r, const unsigned char *payload, unsigned long n) {
	struct ccs_object *obj;

	if (r->slot < 0 || r->slot >= CCS_MAX_SLOTS)
		return -EINVAL;
	obj = slots[r->slot];     
	if (!obj)
		return -ENOENT;
	if (n > sizeof(struct ccs_object))
		n = sizeof(struct ccs_object);
	memcpy(obj, payload, n); 

	return 0;
}

static long do_sync(struct ccs_req *r) {
	struct ccs_object *obj;

	if (r->slot < 0 || r->slot >= CCS_MAX_SLOTS)
		return -EINVAL;
	obj = slots[r->slot];    
	if (!obj)
		return -ENOENT;
	if (obj->wp)
		*(obj->wp) = obj->wv; 

	return 0;
}

static long do_peek(struct ccs_req *r, unsigned char *out, unsigned long *pn) {
	struct ccs_object *obj;
	unsigned long n = *pn;

	if (r->slot < 0 || r->slot >= CCS_MAX_SLOTS)
		return -EINVAL;
	obj = slots[r->slot];     /*  for dangling  */
	if (!obj)
		return -ENOENT;
	if (n > sizeof(struct ccs_object))
		n = sizeof(struct ccs_object);
	memcpy(out, obj, n);     
	*pn = n;

	return 0;
}

static int ccs_setsockopt(struct socket *sock, int level, int optname, sockptr_t optval, unsigned int optlen) {
	struct ccs_req r;
	unsigned char *kbuf = NULL;
	unsigned long paylen = 0;
	long ret;

	if (level != SOL_CCS)
		return -ENOPROTOOPT;
	if (optlen < sizeof(r))
		return -EINVAL;
	if (copy_from_sockptr(&r, optval, sizeof(r)))
		return -EFAULT;
	paylen = optlen - sizeof(r);
	if (paylen > sizeof(struct ccs_object))
		paylen = sizeof(struct ccs_object);
	if (optname == CCS_O_POKE && paylen) {
		kbuf = kmalloc(paylen, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;
		if (copy_from_sockptr_offset(kbuf, optval, sizeof(r), paylen)) {
			kfree(kbuf);
			return -EFAULT;
		}
	}
	mutex_lock(&ccs_lock);
	switch (optname) {
		case CCS_O_ALLOC:    
			ret = do_alloc(&r, GFP_KERNEL);          
			break;
		case CCS_O_ALLOC_CG: 
			ret = do_alloc(&r, GFP_KERNEL_ACCOUNT);  
			break;
		case CCS_O_FREE:     
			ret = do_free(&r);                       
			break;
		case CCS_O_POKE:     
			ret = do_poke(&r, kbuf, paylen);         
			break;
		case CCS_O_SYNC:     
			ret = do_sync(&r);                       
			break;
		default:             
			ret = -ENOPROTOOPT;                      
			break;
	}
	mutex_unlock(&ccs_lock);
	kfree(kbuf);

	return (int)ret;
}

static int ccs_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen) {
	struct ccs_req r;
	unsigned char kbuf[sizeof(struct ccs_object)];
	unsigned long n;
	int ulen;
	long ret;

	if (level != SOL_CCS)
		return -ENOPROTOOPT;
	if (optname != CCS_O_PEEK)
		return -ENOPROTOOPT;
	if (get_user(ulen, optlen))
		return -EFAULT;
	if (ulen < (int)sizeof(r))
		return -EINVAL;
	if (copy_from_user(&r, optval, sizeof(r)))
		return -EFAULT;
	n = r.len;
	if (n > sizeof(struct ccs_object))
		n = sizeof(struct ccs_object);
	if ((int)(sizeof(r) + n) > ulen)
		n = ulen - sizeof(r);
	mutex_lock(&ccs_lock);
	ret = do_peek(&r, kbuf, &n);
	mutex_unlock(&ccs_lock);
	if (ret)
		return (int)ret;
	if (copy_to_user(optval + sizeof(r), kbuf, n))
		return -EFAULT;
	ulen = sizeof(r) + n;
	if (put_user(ulen, optlen))
		return -EFAULT;

	return 0;
}

static struct proto ccs_proto = {
	.name     = "CCS",
	.owner    = THIS_MODULE,
	.obj_size = sizeof(struct sock),
};

static int ccs_sock_release(struct socket *sock) {
	struct sock *sk = sock->sk;

	if (sk) {
		sock_orphan(sk);
		sock->sk = NULL;
		sk_free(sk);
	}

	return 0;
}

static const struct proto_ops ccs_ops = {
	.family     = PF_CCS,
	.owner      = THIS_MODULE,
	.release    = ccs_sock_release,
	.bind       = sock_no_bind,
	.connect    = sock_no_connect,
	.socketpair = sock_no_socketpair,
	.accept     = sock_no_accept,
	.getname    = sock_no_getname,
	.poll       = datagram_poll,
	.ioctl      = sock_no_ioctl,
	.listen     = sock_no_listen,
	.shutdown   = sock_no_shutdown,
	.setsockopt = ccs_setsockopt,
	.getsockopt = ccs_getsockopt,
	.sendmsg    = sock_no_sendmsg,
	.recvmsg    = sock_no_recvmsg,
	.mmap       = sock_no_mmap,
};

static int ccs_create(struct net *net, struct socket *sock, int protocol, int kern) {
	struct sock *sk;

	sk = sk_alloc(net, PF_CCS, GFP_KERNEL, &ccs_proto, kern);
	if (!sk)
		return -ENOMEM;
	sock_init_data(sock, sk);
	sock->ops       = &ccs_ops;
	sock->state     = SS_UNCONNECTED;
	sk->sk_family   = PF_CCS;
	sk->sk_protocol = protocol;

	return 0;
}

static const struct net_proto_family ccs_family = {
	.family = PF_CCS,
	.create = ccs_create,
	.owner  = THIS_MODULE,
};

static int __init ccs_init(void) {
	int rc;

	rc = proto_register(&ccs_proto, 0);
	if (rc) {
		pr_err("ccsheaf: proto_register gagal %d\n", rc);
		return rc;
	}
	rc = sock_register(&ccs_family);
	if (rc) {
		proto_unregister(&ccs_proto);
		return rc;
	}

	return 0;
}

static void __exit ccs_exit(void) {
	int i;

	mutex_lock(&ccs_lock);
	for (i = 0; i < CCS_MAX_SLOTS; i++)
		slots[i] = NULL;
	mutex_unlock(&ccs_lock);
	sock_unregister(PF_CCS);
	proto_unregister(&ccs_proto);
}

module_init(ccs_init);
module_exit(ccs_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonius (w1sdom / sw0rdm4n) - bluedragonsec.com");
MODULE_DESCRIPTION("UAF vulner lkm for cross cache research in kernel 7.0");
