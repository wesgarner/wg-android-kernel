EXTRA_CFLAGS	:=	-DCONFIG_BLK_DEV_RAMZSWAP_STATS \
			-g -Wall

KERNEL_BUILD_PATH ?= "/home/wesgarner/src/wg-android-kernel"

obj-m	+=	sub-projects/allocators/xvmalloc-kmod/xvmalloc.o \
		ramzswap.o

all:
	make -C $(KERNEL_BUILD_PATH) \
		M=$(PWD)/sub-projects/allocators/xvmalloc-kmod modules
	make -C $(KERNEL_BUILD_PATH) M=$(PWD) modules
	make -C sub-projects/rzscontrol
	@ln -sf sub-projects/allocators/xvmalloc-kmod/xvmalloc.ko

doc:
	make -C sub-projects/rzscontrol doc

clean:
	make -C $(KERNEL_BUILD_PATH) M=$(PWD) clean
	make -C $(KERNEL_BUILD_PATH) M=$(PWD)/sub-projects/allocators/xvmalloc-kmod clean
	make -C sub-projects/rzscontrol clean
	@rm -rf *.ko
