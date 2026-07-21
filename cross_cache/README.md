# Cross Cache UAF Exploitation pOc for Linux 7.0

>Antonius (w1sdom / ev1lut10n / sw0rdm4n / ringlayer / robotsoft) - bluedragonsec.com

## LPE SERIES

### cross_cache_cred

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using cred overwrite for LPE. Tested on linux 7.0 - lubuntu 26
>
>Cross-cache technique : volume overflow

### cross_cache_dirtypagetable_deterministic

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using DirtyPageTable for LPE.  
Deterministic cross cache using kratnowl 6-pool. Tested on linux 7.0 - lubuntu 26.
>>
>Cross-cache technique : kratnowl 6-pool


### cross_cache_dirtycred_deterministic

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using dirtycred f_mode overwrite for LPE. Without information leak at all. Deterministic cross cache using kratnowl 6-pool. Tested on linux 7.0 - lubuntu 26.
>
>Cross-cache technique : kratnowl 6-pool


### cross_cache_pagejack_deterministic

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using bridge object.  Deterministic cross cache using kratnowl 6-pool. Tested on linux 7.0 - lubuntu 26.
>
>Cross-cache technique : kratnowl 6-pool


### cross_cache_modprobe_socket_deterministic

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. Communication via socket. An UAF read for information leak & UAF write for LPE. Deterministic cross cache using kratnowl 6-pool. Tested on linux 7.0 - lubuntu 26.
>
>Cross-cache technique : kratnowl 6-pool

### cross_cache_dirtypagetable

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using DirtyPageTable for LPE. Tested on linux 7.0 - lubuntu 26.
>
>Cross-cache technique : volume overflow

### cross_cache_socket2

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves.  Cross-cache strategy is adapted from cross-x (complete free).
>
>Tested on linux 7.0 - lubuntu 26.
>
>Cross-cache technique : Complete Free

### cross_cache_dirtycred2

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using DirtyCred f_mode overwrite for LPE. Without information leak at all. Cross-cache strategy is adapted from cross-x (complete free). Tested on linux 7.0 - lubuntu 26.

### cross_cache_dirtycred

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using dirtycred f_mode overwrite for LPE. Without information leak at all. Tested on linux 7.0 - lubuntu 26.
>
>Cross-cache technique : volume overflow

### cross_cache_hijack1

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using function pointer hijack for LPE. An UAF read for information leak & UAF write for LPE. Tested on linux 7.0 - lubuntu 26.
>
>Cross-cache technique : volume overflow

### cross_cache_hijack2_no_sheaf

>Cross cache UAF exploitation pOc for linux kernel 7.0 when the object has no sheaves, using function pointer hijack for LPE. An UAF read for information leak & UAF write for LPE. Tested on linux 7.0 - lubuntu 26. Nothing special here.

### cross_cache_modprobe

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. An UAF read for information leak & UAF write for LPE. Tested on linux 7.0 - lubuntu 26.
>
>Cross-cache technique : volume overflow

### cross_cache_socket

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. Communication via socket. An UAF read for information leak & UAF write for LPE. Tested on linux 7.0 - lubuntu 26.
>
>Cross-cache technique : volume overflow

### cross_cache_socket2

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. Communication via socket.
Cross-Cache Mechanism using Complete Free - Adapted from Cross-x. Tested on linux 7.0 - lubuntu 26.
>
>Cross-cache technique : Complete Free


## INFORMATION LEAK SERIES

### cross_cache_read_leak_xattr

>Cross cache UAF read information leak pOc using simple_xattr. No LPE, just info leak. Tested on linux 7.0 - lubuntu 26.
>
>Cross-cache technique : volume overflow
