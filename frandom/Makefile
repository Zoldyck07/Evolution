KERNEL_DIR=/home/neo/android/kernel/

obj-m := frandom.o
PWD := $(shell pwd)
default:
	$(MAKE) ARCH=arm CROSS_COMPILE=/home/neo/android/android_prebuilt_toolchains/arm-eabi-4.4.3/bin/arm-eabi- -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules
clean:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) clean
