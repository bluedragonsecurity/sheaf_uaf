## SHEAFJACK SERIES

>Antonius (w1sdom / ev1lut10n / sw0rdm4n / ringlayer / robotsoft / d4r3d3v1l / 黑蝎子) - bluedragonsec.com
>
>https://github.com/bluedragonsecurity
>
>SheafJack v1 only applicable when the victim cache "has a constructor" or uses this flag : "SLAB_TYPESAFE_BY_RCU". 
>when a victim cache has a constructor or uses SLAB_TYPESAFE_BY_RCU flag, init_on_alloc doesn't zeroes during allocation.
>Meanwhile for SheafJack v2, INIT_ON_ALLOC doesn't affect the exploitation technique.
>


# UAF_WRITE

>Some proof of concepts (pOc) to demonstrate SheafJack to exploit UAF in linux 7.0.
>

### cross_cache_sheafjack_v1_elastic_pipe_siphon
>SheafJack v1 Demo to Exploit a UAF in linux 7.0.
>
>Cross Cache technique : SheavesSiphon
>
>LPE Tech : Sheafjack v1 + deep sheaf poisoning.  Tested on linux 7.0 - lubuntu 26
>
>n.b : SheafJack v1 works for cache with SLAB_TYPESAFE_BY_RCU or cache with ctor
>
>for a broader target, use SheafJack v2 !!!


### same_cache_sheafjack_v1_elastic_pipe

>SheafJack v1 Demo to Exploit a UAF in linux 7.0.
>
>Same Cache UAF Reclaim
>
>LPE Tech : Sheafjack v1 + deep sheaf poisoning.  Tested on linux 7.0 - lubuntu 26
>
>n.b : SheafJack v1 works for cache with SLAB_TYPESAFE_BY_RCU or cache with ctor
>
>for a broader target, use SheafJack v2 !!!


# AARW 

>This is just some proof of concepts to validate the exploitation techniques but everything in AARW directory is still implemented using AARW.
>
>Results : LPE.
>
>Just like the name suggests, this is just for sheafjack testing using arbitrary read and write.
>

### sheafjack_v1_btrfs_aarw_test
> SheafJack v1 - direct objects[] overwrite testing - non UAF, just AARW for testing & validating the exploitation technique. 
>
> Result : LPE.  Tested on linux 7.0 - lubuntu 26
>
>n.b : SheafJack v1 works for cache with SLAB_TYPESAFE_BY_RCU or cache with ctor
>
>for a broader target, use SheafJack v2 !!!

### sheafjack_v1_modprobe_aarw_test
> SheafJack v1 - direct objects[] overwrite testing - non UAF, just AARW for testing & validating the exploitation technique.
>
> Result : LPE. Tested on linux 7.0 - lubuntu 26
>
>n.b : SheafJack v1 works for cache with SLAB_TYPESAFE_BY_RCU or cache with ctor
>
>for a broader target, use SheafJack v2 !!!
