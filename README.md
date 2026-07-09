# UAF Exploitation in Sheaves Era - The Exploitation pOc Artifacts

(c))Antonius (w1sdom / sw0rdm4n / ev1lut10n) - www.bluedragonsec.com - 2026


>This repository is about Use After Free Exploitation pOc specific to the new slub sheaves architecture in the linux kernel 7.0 on x86_64 architecture. 

>Everything designed here is specific for linux kernel version 7.0. Please note that some lab exploits here might need more than 1 attempt, since I haven't design it to be highly reliable yet. To test, insmod the lkm then run the exploit. Tested and works good for lubuntu 26 with linux kernel 7.0 (custom build, mitigation level is similar to lubuntu 26 with standard mitigation where kaslr on and kptr_restrict = 2).

>n.b:
<pre>
- Some exploits might need to run more than once if failed.
- When you have tested some exploits, the next exploit might fails, you need to restart your machine before continue.
- For lab source code, you need to compile the lkm with "make" and then "insmod" the .ko before testing the exploit.
- To compile the exploit, please read the source, mostly : gcc -static -o exploit exploit.c
  or just type : make
</pre>


### vm-linux-7.0.tar.bz2

>The kernel and other supporting files, if you want to test the exploit. Suggested distro : lubuntu 26 in Qemu. 

## pOc Collections for Linux Kernel 7.0 Slub Sheaves Exploitation Series

###cross_cache

>Cross cache UAF exploitation pOc for slub sheaves.

###same_cache

>Same cache UAF exploitation pOc for slub sheaves.

###elastic_objects

>Same cache UAF exploitation p0c using elastic object to build AARW primitives.

###sheafjack

>SheafJack is a novel UAF exploitation technique for slub sheaves.


