#!/bin/bash

# unuse_ramzswap (run as *root*)
#     Unloads ramzswap and related modules.
#     Assmes that you already swapoff'ed all ramzswap devices.

LSMOD_BIN=/sbin/lsmod
RMMOD_BIN=/sbin/rmmod
SWAPOFF_BIN=/sbin/swapoff

EXIST=`$LSMOD_BIN | grep ramzswap`
if [ "$EXIST" = "" ]; then
	echo "ramzswap module not loaded"
	exit 0
fi

echo "Unloading modules ..."
$RMMOD_BIN ramzswap
$RMMOD_BIN xvmalloc

echo "Done!"
