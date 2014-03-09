.PHONY: all clean
obj-m += fullnat.o

all:
	$(MAKE) -C /lib/modules/`uname -r`/build M=`pwd` modules

clean:
	$(MAKE) -C /lib/modules/`uname -r`/build M=`pwd` clean
