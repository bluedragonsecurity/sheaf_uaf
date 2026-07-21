obj-m += vmsg.o
ccflags-y := -g -O2

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

load: all
	-sudo rmmod vmsg 2>/dev/null
	sudo insmod vmsg.ko
	sudo dmesg | tail -3

unload:
	-sudo rmmod vmsg
	sudo dmesg | tail -2
