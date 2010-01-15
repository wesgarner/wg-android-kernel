#!/bin/bash

#
# Usage: load_modules.sh <NUM_DEVICES>
# Example: load_modules.sh 4
#     Loads all modules and creates 4 ramzswap devices.
#

#
# Loads ramzswap module and all its dependencies:
#  1) LZO de/compressor:		lzo_compress.ko, lzo_decompress.ko
#  2) xvMalloc allocator:		xvmalloc.ko
#  3) virtual block device driver:	ramzswap.ko
#
# ramzswap module accepts following parameters:
#  1) NUM_DEVICES=n (optional): this parameter specifies how many ramzswap
#         devices are created. The devices are named as /dev/ramzswapX where
#         'X' is 0, 1, 2, ... NUM_DEVICES-1
#     Default: 1
#

##
# Script begin
##

# ramzswap module params
NUM_DEVICES="$1"

if [ -z "$NUM_DEVICES" ]; then
	NUM_DEVICES="1"
fi

LSMOD_BIN=/sbin/lsmod
INSMOD_BIN=/sbin/insmod
MODPROBE_BIN=/sbin/modprobe
SWAPON_BIN=/sbin/swapon
UDEVADM_BIN=/sbin/udevadm

EXIST=`$LSMOD_BIN | grep ramzswap`
if [ -n "$EXIST" ]; then
	echo "ramzswap module already loaded."
	exit 0
fi

echo "Loading modules ..."
$MODPROBE_BIN -q lzo_compress || (echo "LZO compress module not found"; exit 0)
$MODPROBE_BIN -q lzo_decompress || (echo "LZO decompress module not found"; exit 0)
$INSMOD_BIN ./xvmalloc.ko
$INSMOD_BIN ./ramzswap.ko NUM_DEVICES="$NUM_DEVICES"

# /dev/ramzswapX devices are not available immediately after
# insmod returns. So, let udev complete its work before we start
# using devices.
if [ -f "$UDEVADM_BIN" ]; then
	$UDEVADM_BIN settle
else
	sleep 2 
fi

echo "Done!"
