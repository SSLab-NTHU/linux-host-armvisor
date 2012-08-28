#
# Makefile for Kernel-based Virtual Machine module
#
EXTRA_CFLAGS += -Ivirt/kvm -Iarch/arm/kvm

common-objs-y = $(addprefix ../../../virt/kvm/, kvm_main.o coalesced_mmio.o)
common-objs-$(CONFIG_KVM_TRACE) = $(addprefix ../../../virt/kvm/, kvm_trace.o)

kvm-objs := $(common-objs-y) arm.o vsoft_vcpu.o emulate_arm.o vsoft_trap.o vsoft-entry.o vsoft_mmu.o \
vsoft_nonpaging.o vsoft_mmu_hpte.o vsoft_paging_v6.o profile.o mmu.o 
obj-y += kvm.o

