ifeq ($(CONFIG_MSM_AMSS_SUPPORT_256MB_EBI1),y)
zreladdr-y		:= 0x19208000
params_phys-y		:= 0x19200100
initrd_phys-y		:= 0x19A00000
else
zreladdr-y		:= 0x10008000
params_phys-y		:= 0x10000100
initrd_phys-y		:= 0x10800000
endif
