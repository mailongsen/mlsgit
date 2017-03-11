obj-m := src/ddkernel.o
	KERNELBUILD :=/lib/modules/$(shell uname -r)/build
default:  
	make -C /usr/src/linux-headers-$(shell uname -r) M=$(shell pwd) modules
clean:  
	rm -rf *.o *.ko *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions  *unsigned src/*.o src/*.ko src/*.mod.c
