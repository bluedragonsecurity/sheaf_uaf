#Cross Cache UAF Exploitation pOc for Linux 7.0

>Antonius (w1sdom / ev1lut10n / sw0rdm4n / ringlayer / robotsoft) - bluedragonsec.com

##LPE SERIES

### cross_cache_cred

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using cred overwrite for LPE. 

### cross_cache_dirtypagetable_deterministic

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using DirtyPageTable for LPE. 
Deterministic cross cache using kratnowl strategy.


### cross_cache_dirtycred_deterministic

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using dirtycred f_mode overwrite for LPE. Without information leak at all. Deterministic cross cache using kratnowl strategy.

### cross_cache_pagejack_deterministic

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using bridge object.  Deterministic cross cache using kratnowl strategy.


### cross_cache_modprobe_socket_deterministic

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. Communication via socket. An UAF read for information leak & UAF write for LPE. Deterministic cross cache using kratnowl strategy.

### cross_cache_dirtypagetable

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using DirtyPageTable for LPE. 

### cross_cache_socket2

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves. ret2buddy is accomplished by draining the main sheaf, spare sheaf, saturate the barn, once return to slab, I create a condition where kernel do a jmp to slab_empty to discard_slab() hence return to buddy. lulz.

### cross_cache_dirtycred2

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using DirtyCred f_mode overwrite for LPE. Without information leak at all. The secret recipe for cross cache in kernel 7 ? create a condition where (!new.inuse && n->nr_partial >= s->min_partial), this is going to make a jmp to slab_empty ! So what's there at slab_empty ??? discard_slab() -> this one is the key for returning to buddy !!! 

### cross_cache_dirtycred

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using dirtycred f_mode overwrite for LPE. Without information leak at all.

### cross_cache_hijack1

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using function pointer hijack for LPE. An UAF read for information leak & UAF write for LPE.

### cross_cache_hijack2_no_sheaf

>Cross cache UAF exploitation pOc for linux kernel 7.0 when the object has no sheaves, using function pointer hijack for LPE. An UAF read for information leak & UAF write for LPE.

### cross_cache_modprobe

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. An UAF read for information leak & UAF write for LPE.

### cross_cache_socket

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. Communication via socket. An UAF read for information leak & UAF write for LPE.

### cross_cache_socket2

>Cross cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. Communication via socket.


##INFORMATION LEAK SERIES

### cross_cache_read_leak_xattr

>Cross cache UAF read information leak pOc using simple_xattr. No LPE, just info leak.
