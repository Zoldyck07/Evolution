#!/bin/bash
TOOLCHAIN="/home/zoldyck/android/Evolution/toolchains/arm-eabi-linaro-4.6.2/bin/arm-eabi"
MODULES_DIR="/home/zoldyck/android/Evolution/modules"
KERNEL_DIR="/home/zoldyck/android/Evolution"
echo " Znxt Build Script"
echo "  Znxt TEAM " 
echo " Copyright "
make ARCH=arm CROSS_COMPILE=$TOOLCHAIN- Znxt_defconfig
make ARCH=arm CROSS_COMPILE=$TOOLCHAIN- -j4
if [ -a $KERNEL_DIR/arch/arm/boot/zImage ];
then
echo "Copying modules"
find . -name '*.ko' -exec cp {} $MODULES_DIR/ \;
cd $MODULES_DIR
echo "Stripping modules for size"
$TOOLCHAIN-strip --strip-unneeded *.ko
cd $KERNEL_DIR
else
echo "Dafuq its failed! Fix the errors!"
fi
