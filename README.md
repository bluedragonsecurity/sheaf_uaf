# UAF Exploitation in Sheaves Era - The Exploitation pOc Artifacts

by : Antonius (w1sdom / sw0rdm4n / ev1lut10n) - www.bluedragonsec.com


>This repository is about use after free exploitation pOc specific to the new slub sheaves architecture in the linux kernel 7.0 on x86_64 architecture. The sheaves architecture changes the concept of modern slub exploitation. A freed object is no longer handed straight back to the slab freelist. Instead, it is parked in a per-cpu sheaf and surplus sheaves are buffered in a per-node structure called the barn.

>Everything designed here is specific for linux kernel version 7.0. Please note that some lab exploits here might need more than 1 attempt, since I haven't design it to be highly reliable yet. To test, insmod the lkm then run the exploit. Tested and works good for lubuntu 26 with linux kernel 7.0 (custom build, mitigation level is simlar to lubuntu 26 standard mitigation), kaslr on and kptr_restrict = 2.

>n.b:
<pre>
- Some exploits might need to run more than once if failed (some cross cache type).
- When you have tested some exploits, the next exploit might failed, you need to restart your machine for testing the failed one.
  (mostly cross cache type).
- For lab source code, you need to compile the lkm with "make" and then "insmod" the .ko before testing the exploit.
- To compile the exploit, please read the source, mostly : gcc -static -o exploit exploit.c
</pre>


### vm.tar.bz2

>The kernel and other supporting files, if you want to test the exploit. Suggested distro : lubuntu 26 in Qemu. Use the vmlinux from vm.tar.bz2

## pOc Collections for Linux Kernel 7.0 Slub Sheaves Exploitation Series

### cross_cache_cred

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using cred overwrite for LPE. 

### cross_cache_socket2

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves. ret2buddy is accomplished by draining the main sheaf, spare sheaf, saturate the barn, once return to slab, I create a condition where kernel do a jmp to slab_empty to discard_slab() hence return to buddy. lulz.

### cross_cache_dirtycred2

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using dirtycred f_mode overwrite for LPE. Without information leak at all. The secret recipe for cross cache in kernel 7 ? create a condition where (!new.inuse && n->nr_partial >= s->min_partial), this is going to make a jmp to slab_empty ! So what's there at slab_empty ??? discard_slab() -> this one is the key for returning to buddy !!! 

### cross_cache_dirtycred

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using dirtycred f_mode overwrite for LPE. Without information leak at all.

### cross_cache_hijack1

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using function pointer hijack for LPE. An UAF read for information leak & UAF write for LPE.

### cross_cache_hijack2_no_sheaf

>Cross cache UAF exploitation pOc for linux kernel 7.0 when the object has no sheaves, using function pointer hijack for LPE. An UAF read for information leak & UAF write for LPE.

### cross_cache_modprobe

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. An UAF read for information leak & UAF write for LPE.

### cross_cache_read_leak_xattr

>Cross cache UAF read information leak pOc using simple_xattr. No LPE, just info leak.

### cross_cache_socket

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. Communication via socket. An UAF read for information leak & UAF write for LPE.

### same_cache_dirtycred

>Same cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using dirtycred f_mode overwrite for LPE. Without information leak at all.

### same_cache_cred

>Same cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using cred overwrite for LPE. 

### same_cache_hijack

>Same cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using function pointer hijack for LPE. An UAF read for information leak & UAF write for LPE.

### same_cache_leak2lpe

>Same cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. Converting a single UAF write into information leak & LPE.

### same_cache_modprobe

>Same cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. An UAF read for information leak & UAF write for LPE.

### same_cache_read_leak_seq_file

>Same cache UAF read information leak pOc using seq_file. No LPE, just info leak.

### same_cache_socket

>Same cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. Communication via socket. An UAF read for information leak & UAF write for LPE.

### same_cache_write_leak_user_key

>Same cache UAF write information leak pOc using user_key_payload. No LPE, just info leak. Converting an UAF write into information leak.

### same_cache_write_leak_xattr

>Same cache UAF write information leak pOc using simple_xattr. No LPE, just info leak. Converting an UAF write into information leak.
