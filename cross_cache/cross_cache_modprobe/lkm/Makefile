obj-m += ccsheaf.o

# Disable stack protector & fortify supaya pola bug bersih dan mudah dianalisa
ccflags-y := -fno-stack-protector -D_FORTIFY_SOURCE=0 -g

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
