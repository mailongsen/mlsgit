 obj-m := dd_kernel.o
	KERNELBUILD :=/lib/modules/$(shell uname -r)/build  
default:  
	make -C /usr/src/kernels/2.6.32-220.2.1.el6.x86_64 M=$(shell pwd) modules  
clean:  
	rm -rf *.o *.ko *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions  *unsigned
