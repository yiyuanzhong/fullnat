.PHONY: all clean
obj-m += fullnat.o
fullnat-objs := main.o procfs.o rip.o

all:
	$(MAKE) -C /lib/modules/`uname -r`/build M=`pwd` modules

clean:
	$(MAKE) -C /lib/modules/`uname -r`/build M=`pwd` clean
