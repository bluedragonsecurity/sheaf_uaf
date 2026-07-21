# UAF Exploitation in Sheaves Era - The Exploitation pOc Artifacts

(c) Antonius (w1sdom / sw0rdm4n / ev1lut10n) - www.bluedragonsec.com - 2026


>This repository is about Use After Free Exploitation pOc specific to the new slub sheaves architecture in the linux kernel 7.0 on x86_64 architecture. 

>Everything designed here is specific for linux kernel version 7.0. Please note that some lab exploits here might need more than 1 attempt,
while some exploits may work in 1 try. 
>
>To test, insmod the lkm then run the exploit. Tested and works good for lubuntu 26 with linux kernel 7.0 (custom build, mitigation level is similar to lubuntu 26 with standard mitigation where kaslr on and kptr_restrict = 2).
>
>For real world exploits, some exploit might need a specific requirements and some of the exploits might need more than 1 try to succeed or might need
>a long time to succeed.

>n.b:
<pre>
- Some exploits might need to run more than once if failed.
- When you have tested some exploits, the next exploit might fails, 
  you need to restart your machine before continue.
- For lab source code, you need to compile the lkm with "make"  
  and then "insmod" the .ko before testing the exploit.
- To compile the exploit : make
</pre>


### vmlinux

>Suggested distro : lubuntu 26 in Qemu. 
>Linux kernels with default mitigations enabled.
>Mitigation level is similar to default ubuntu 26 or lubuntu 26 distro.
>
>kaslr on & kptr_restrict = 2.
>
>HARDENED_USERCOPY enabled
>
>RANDOM_KMALLOC_CACHES enabled
>
>INIT_ON_ALLOC enabled
>
>INIT_ON_FREE off

## Contents : 

#### vmlinux-7-damn-vulnerable-uaf
>Linux kernel 7.0 with default mitigations enabled.
>Mitigation level is similar to default ubuntu 26 or lubuntu 26 distro.
>This is a linux 7.0 kernel where I removed all patches related to UAF.

#### vmlinux-7.0
>Linux kernel 7.0 with default mitigations enabled.
>Mitigation level is similar to default ubuntu 26 or lubuntu 26 distro.
>Standard linux kernel with some UAF(s) patched.

#### vmlinux-7.0-rc1
>Linux kernel 7.0-rc1 with default mitigations enabled.
>Mitigation level is similar to default ubuntu 26 or lubuntu 26 distro.
>This one is used for testing sheafjack v2 only.

## pOc Collections for Linux Kernel 7.0 Slub Sheaves Exploitation Series

### cross_cache

>Cross cache UAF exploitation pOc for slub sheaves. Tested on linux kernel 7.0 - lubuntu 26.

### same_cache

>Same cache UAF exploitation pOc for slub sheaves. Tested on linux kernel 7.0 - lubuntu 26.

### elastic_objects

>Same cache UAF exploitation p0c using elastic object to build AARW primitives. Tested on linux kernel 7.0 - lubuntu 26.

### sheafjack

>SheafJack is a novel UAF exploitation technique for slub sheaves. Tested on linux kernel 7.0 & Linux Kernel 7.0-rc1 - lubuntu 26.

### exploits

>Real world exploits - for demonstrating UAF based exploits in linux 7.0. Tested on linux kernel 7.0 - lubuntu 26.
