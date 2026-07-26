# same_cache_write_leak_vmemmap

>Same cache UAF write information leak pOc using simple_xattr. No LPE, just info leak. Converting an UAF write into information leak.
For Linux 7.0. more complete leaks : vmemmap_base, page offset

Compile the LKM and then insmod before run the exploit.

<pre>
┌──(robohax㉿robohax-20bws2ng00)-[/run/…/robohax/Desktop/KERNEL/linux-7.0]
└─$ nm vmlinux | grep -E "anon_pipe_buf_ops"
ffffffff82852ec0 d anon_pipe_buf_ops
$ ./exploit 0xffffffff82852ec0
</pre>

![leak](leak.png)
