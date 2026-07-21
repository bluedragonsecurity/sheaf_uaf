# Same Cache UAF Exploitation pOc for Linux 7.0

>Antonius (w1sdom / ev1lut10n / sw0rdm4n / ringlayer / robotsoft) - bluedragonsec.com

## LPE SERIES

### same_cache_dirtycred

>Same cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using DirtyCred f_mode overwrite for LPE. Without information leak at all. Tested on linux 7.0 - lubuntu 26.

### same_cache_pagejack

>Same cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using PageJack for LPE. This technique can be used to avoid the need to "return to buddy allocator" leveraging bridged object. Tested on linux 7.0 - lubuntu 26.

### same_cache_cred

>Same cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using cred overwrite for LPE.  Tested on linux 7.0 - lubuntu 26.

### same_cache_hijack

>Same cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using function pointer hijack for LPE. An UAF read for information leak & UAF write for LPE. Tested on linux 7.0 - lubuntu 26.

### same_cache_leak2lpe

>Same cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. Converting a single UAF write into information leak & LPE. Tested on linux 7.0 - lubuntu 26.

### same_cache_modprobe

>Same cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. An UAF read for information leak & UAF write for LPE. Tested on linux 7.0 - lubuntu 26.

### same_cache_read_leak_seq_file

>Same cache UAF read information leak pOc using seq_file. No LPE, just info leak. Tested on linux 7.0 - lubuntu 26.

### same_cache_socket

>Same cache UAF exploitation pOc for linux kernel 7.0 slub sheaves using modprobe for LPE. Communication via socket. An UAF read for information leak & UAF write for LPE. Tested on linux 7.0 - lubuntu 26.


## INFORMATION LEAK SERIES

### same_cache_write_leak_vmemmap

>Same cache reclaim via simple_xattr. Pipe_buffer spray for structural extraction of .text and vmemmap pointers at known offsets within the pipe_buffer layout. Tested on linux 7.0 - lubuntu 26.

### same_cache_write_leak_user_key

>Same cache UAF write information leak pOc using user_key_payload. No LPE, just info leak. Converting an UAF write into information leak. Tested on linux 7.0 - lubuntu 26.

### same_cache_write_leak_xattr

>Same cache UAF write information leak pOc using simple_xattr. No LPE, just info leak. Converting an UAF write into information leak. Tested on linux 7.0 - lubuntu 26.


