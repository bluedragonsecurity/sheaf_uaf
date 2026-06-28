obj-m += ccfile.o
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
load: all
	-sudo rmmod ccfile 2>/dev/null
	sudo insmod ./ccfile.ko
	sudo dmesg | tail -3
	ls -l /dev/ccfile
unload:
	-sudo rmmod ccfile
