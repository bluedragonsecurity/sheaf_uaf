## ELASTIC OBJECT SERIES

>Antonius (w1sdom / ev1lut10n / sw0rdm4n / ringlayer / robotsoft) - bluedragonsec.com

Tested elastic object vehicles that can be used to build AARW primitives in linux 7.0.

### same_cache_elastic_imu
> The best elastic object for building AARW primitives for linux 7.0. Vehicle: io_mapped_ubuf from io_uring IORING_REGISTER_BUFFERS. Tested on linux 7.0 - lubuntu 26.

### same_cache_elastic_pipe_cred
> Build AARW primitives using pipe_buffer elastic object, then overwrite the credentials. Tested on linux 7.0 - lubuntu 26.

### same_cache_elastic_pipe_modprobe
> Build AARW primitives using pipe_buffer elastic object, then overwrite the modprobe_path. Tested on linux 7.0 - lubuntu 26.

### cross_cache_elastic_imu_deterministic
> Build AARW primitives using io_mapped_ubuf from io_uring IORING_REGISTER_BUFFERS, deterministic cross cache (kratnowl 6-pool). Tested on linux 7.0 - lubuntu 26.

### cross_cache_elastic_pipe_deterministic
> Build AARW primitives using pipe_buffer elastic object, deterministic cross cache (kratnowl 6-pool). Tested on linux 7.0 - lubuntu 26.

### cross_cache_elastic_pipe_siphon
> Build AARW primitives using pipe_buffer elastic object, deterministic cross cache (SheavesSiphon). Tested on linux 7.0 - lubuntu 26.

### cross_cache_elastic_imu_siphon
> Build AARW primitives using io_mapped_ubuf from io_uring IORING_REGISTER_BUFFERS, deterministic cross cache (SheavesSiphon). Tested on linux 7.0 - lubuntu 26.
