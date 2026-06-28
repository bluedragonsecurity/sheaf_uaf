obj-m += ccxfile.o

ccflags-y := -fno-stack-protector -D_FORTIFY_SOURCE=0 -g

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load: all
	-sudo rmmod ccxfile 2>/dev/null
	sudo insmod ./ccxfile.ko
	sudo dmesg | tail -3
	ls -l /dev/ccxfile

unload:
	-sudo rmmod ccxfile
