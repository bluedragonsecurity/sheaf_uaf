# UAF Exploitation in The Sheaves Era - The Exploitation pOc Artifacts
<hr style="width: 100%; border: none; border-top: 1px solid #ccc; margin: 20px 0;">
"A Guide into Linux Kernel 7.* UAF Exploitation"
<hr style="width: 100%; border: none; border-top: 1px solid #ccc; margin: 20px 0;">

>
>(c) Antonius - bluedragonsec.com 2026 - All Rights Reserved
>
> Nicknames : w1sdom, sw0rdm4n, ev1lut10n, d4r3d3v1l, jck.marshall (1 time usage), ringlayer, robotsoft, mranton, >黑蝎子, Prof. Robotsoft, Mr. Robot 
>
><a href="https://www.bluedragonsec.com" style="color: white !important;"><font color="white">www.bluedragonsec.com</font></a>.
>
><a href="https://github.com/bluedragonsecurity" style="color: white !important;"><font color="white">https://github.com/bluedragonsecurity</font></a>.
>
> This repository is about Use After Free Exploitation pOc specific to the new slub sheaves architecture in the linux kernel 7.0 on x86_64 architecture. 

>Everything designed here is specific for linux kernel version 7.0. 
>
>Please note that some lab exploits here might need more than 1 try,
>
>while some exploits may work in 1 try. I have prepared the vmlinux for testing, you can use the vmlinux.
>
>
>To test, insmod the lkm then run the exploit (unless the real world exploits). Tested and works good for lubuntu 26 with linux kernel 7.0 (custom build, mitigation level is similar to lubuntu 26 with standard mitigation where kaslr on and kptr_restrict = 2).  vmlinux-7.0.tar.xz -> use this one.
>
>For real world exploits, some exploit might need a specific requirements and some of the exploits might need more than 1 try to succeed or might need
>a long time to succeed.
>
>
>n.b:
>
<pre>
- Some exploits might need to run 
  more than once if failed.
- When you have tested some exploits, 
  the next exploit might fails, 
  you need to restart your 
  machine before continue.
- For lab source code, you need 
  to compile the lkm with "make"  
  and then "insmod" the .ko 
  before testing the exploit.
- To compile the exploit : make
</pre>
<hr style="width: 100%; border: none; border-top: 1px solid #ccc; margin: 20px 0;">

### vmlinux

>Suggested distro : lubuntu 26 in Qemu.
> 
>Linux kernels with default mitigations enabled.
>
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
>
>SMEP, SMAP, KPTI enabled

## Contents : 

#### vmlinux-7.0
>Linux kernel 7.0 with default mitigations enabled.
>
>Mitigation level is similar to default ubuntu 26 or lubuntu 26 distro.
>
>Standard linux kernel with some UAF(s) patched.
>
>This vmlinux used for every series.
>
>kaslr on, kptr_restrict 2, hardened_usercopy enabled, random_kmalloc_caches enabled, init_on_alloc enabled, init_on_free disabled, smep+smap+kpti enabled

#### vmlinux-7-damn-vulnerable-uaf
>Linux kernel 7.0 with default mitigations enabled.
>
>Mitigation level is similar to default ubuntu 26 or lubuntu 26 distro.
>
>This is a linux 7.0 kernel where I removed all patches related to UAF.
>
>kaslr on, kptr_restrict 2, hardened_usercopy enabled, random_kmalloc_caches enabled, init_on_alloc enabled, init_on_free disabled, smep+smap+kpti enabled

#### vmlinux-7.0-rc1
>Linux kernel 7.0-rc1 with default mitigations enabled.
>Mitigation level is similar to default ubuntu 26 or lubuntu 26 distro.
>
>This one is used for testing sheafjack v2 only (1 lab case).
>
>kaslr on, kptr_restrict 2, hardened_usercopy enabled, random_kmalloc_caches enabled, init_on_alloc enabled, init_on_free disabled, smep+smap+kpti enabled

<hr style="width: 100%; border: none; border-top: 1px solid #ccc; margin: 20px 0;">

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

<hr style="width: 100%; border: none; border-top: 1px solid #ccc; margin: 20px 0;">

# TABLE OF CONTENTS (DETAILED VERSION)

## cross_cache

cross_cache_cred
>
>Cross-cache technique : volume overflow, exp tech : cred overwrite, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_dirtycred
>
>Cross-cache technique : volume overflow, exp tech : DirtyCred, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_dirtycred2
>
>Cross-cache technique : complete free, exp tech : DirtyCred, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_dirtycred_deterministic
>
>Cross-cache technique : kratnowl 6-pool, exp tech : DirtyCred, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_dirtypagetable
>
>Cross-cache technique : volume overflow, exp tech : DirtyPageTable, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_dirtypagetable_deterministic
>
>Cross-cache technique : kratnowl 6-pool, exp tech : DirtyPageTable, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_hijack1
>
>Cross-cache technique : volume overflow, exp tech : function pointer overwrite, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_hijack2_no_sheaf
>
>Cross-cache technique : classic (without sheaves), exp tech : function pointer overwrite, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_modprobe
>
>Cross-cache technique : volume overflow, exp tech : modprobe, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_modprobe_socket_deterministic
>
>Cross-cache technique : kratnowl 6-pool, exp tech : modprobe, comm : socket interface ,target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_pagejack_deterministic
>
>Cross-cache technique : kratnowl 6-pool, exp tech : pagejack, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_read_leak_xattr
>
>Cross-cache technique : volume overflow, exp tech : UAF read -> info leak, vehicle :simple_xattr, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_socket
>
>Cross-cache technique : volume overflow, exp tech : modprobe, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_socket2
>
>Cross-cache technique : complete free, exp tech : modprobe, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>

<hr style="width: 100%; border: none; border-top: 1px solid #ccc; margin: 20px 0;">

## same_cache

same_cache_cred
>
>same cache UAF reclaim, tech : cred overwrite, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
same_cache_dirtycred
>
>same cache UAF reclaim, tech : DirtyCred, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
same_cache_hijack
>
>same cache UAF reclaim, tech : function pointer hijack, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
same_cache_leak2lpe
>
>same cache UAF reclaim, tech : convert UAF write into information leak, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
same_cache_modprobe
>
>same cache UAF reclaim, tech : modprobe, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
>
<br><br>
same_cache_pagejack
>
>same cache UAF reclaim, tech : pagejack, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
>
<br><br>
same_cache_read_leak_seq_file
>
>same cache UAF reclaim, tech : UAF read -> info leak, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
>
<br><br>
same_cache_socket
>
>same cache UAF reclaim, socket interface, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
>
<br><br>
same_cache_write_leak_user_key
>
>same cache UAF reclaim, tech : UAF write -> info leak, vehicle userkey_payload, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
>
<br><br>
same_cache_write_leak_vmemmap
>
>same cache UAF reclaim, tech : UAF write -> info leak, leaks vmemmap, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
>
<br><br>
same_cache_write_leak_xattr
>
>same cache UAF reclaim, tech : UAF write -> info leak, vehicle simple_xattr, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
>
<br><br>

<hr style="width: 100%; border: none; border-top: 1px solid #ccc; margin: 20px 0;">

## elastic_objects
same_cache_elastic_imu
>
>same cache UAF reclaim, build aarw using io_uring, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
same_cache_elastic_pipe_cred
>
>same cache UAF reclaim, build aarw using pipe_buffer, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>

same_cache_elastic_pipe_modprobe
>
>same cache UAF reclaim, build aarw using pipe_buffer, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>

cross_cache_elastic_imu_deterministic
>
>cross cache tech : kratnowl 6-pool, build aarw using io_uring, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>

cross_cache_elastic_pipe_deterministic
>
>cross cache tech : kratnowl 6-pool, build aarw using pipe_buffer, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>

cross_cache_elastic_imu_siphon
>
>cross cache tech : SheavesSiphon, build aarw using io_uring, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu.
>
<br><br>
cross_cache_elastic_pipe_siphon
>
>cross cache tech : SheavesSiphon, build aarw using pipe_buffer, target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu
<br><br>
<hr style="width: 100%; border: none; border-top: 1px solid #ccc; margin: 20px 0;">

## sheafjack

sheafjack_v1_btrfs_aarw_test
>
>SheafJack v1 + Deep Sheaf Poisoning Proof of Concepts (but via AARW), target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu
>
<br><br>
sheafjack_v1_modprobe_aarw_test
>
>SheafJack v1 + Deep Sheaf Poisoning Proof of Concepts (but via AARW), target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu
>
<br><br>
sheafjack_v2_modprobe_linux-7.0-rc1
>
>SheafJack v2 Cache Pointer Overwrite Proof of Concepts (but via AARW), target : linux 7.0-rc (vmlinux-7.0-rc1.tar.xz) - lubuntu 26 in qemu
>
<br><br>
sheafjack_v2_modprobe_linux-7.0
>
>SheafJack v2 Cache Pointer Overwrite Proof of Concepts (but via AARW), target : linux 7.0 (vmlinux-7.0.tar.xz) - lubuntu 26 in qemu
>
<br><br>

<hr style="width: 100%; border: none; border-top: 1px solid #ccc; margin: 20px 0;">

## exploits
CVE-2026-46215-EXPLOIT
>CVE-2026-46215 Linux Kernel UAF Exploit in drm driver, adapted for linux 7.0. Cross Cache Tech : SheavesSiphon
>
<br><br>
entrybleed.c
>kaslr leak via entrybleed
>
<br><br>
CVE-2026-46215-exploit-linux-7.0-uaf-stable
>CVE-2026-46215 Linux Kernel UAF Exploit in drm driver, adapted for linux 7.0. Cross Cache Tech : SheavesSiphon
>
>Should be more stable than previous version ;-p
>
<br><br>

<hr style="width: 100%; border: none; border-top: 1px solid #ccc; margin: 20px 0;">

## scripts
>Scripts for lab research
<pre>
dragon_sheafwatch.py
slab_mon.c
sheaf.py
sheaf_mon.sh
sheaf_dump.py
pipe_spray.c
</pre>

