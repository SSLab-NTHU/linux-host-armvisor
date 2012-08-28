/**
 *  @arm.c
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *  Copyright (c) 2009~2012  SSLab, NTHU
 *
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/kvm_host.h>
#include <asm/kvm_arm.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/ptrace.h>
#include <asm/cputype.h>
//#include "vsoft_mmu.h"
#include "mmu.h"
#include "vsoft_trap.h"
#include "emulate_arm.h"
#define EXCP_IRQ   0x02 /* hardware interrupt pending */
#define EXCP_FIQ    0x10 /* Fast interrupt pending.  */

#define CPSR_BIT57_MASK 0xffffff5f
#define CP15_reg1_EEbit_MASK 0x2000000

struct kvm_guest_opt_regs *kvm_virt_regs = CONFIG_VIRT_REGS_ADDR;
extern struct kvm_vcpu *kvm_vcpu_pointer;

//initial
int kvm_arch_init_vm(struct kvm *kvm)
{
	INIT_LIST_HEAD(&kvm->arch.active_mmu_spages);
	return 0;
}

//called by kvm_vm_ioctl_create_vcpu in kvm_main.c
struct kvm_vcpu *kvm_arch_vcpu_create(struct kvm *kvm, unsigned int id)
{
	struct kvm_vcpu *vcpu;
	int err;

	vcpu = kmem_cache_zalloc(kvm_vcpu_cache, GFP_KERNEL);
	if (!vcpu) {
		err = -ENOMEM;
		goto out;
	}

	err = kvm_vcpu_init(vcpu, kvm, id); //defined in virt/kvm/kvm_main.c
	if (err)
		goto free_vcpu;
	kvm_vcpu_pointer = vcpu;

	// default mode: user mode
	vcpu->arch.virtual_cpsr = (vcpu->arch.virtual_cpsr & 0xffffffe0) | 0x13;
	vcpu->arch.spsr = (vcpu->arch.spsr & 0xffffffe0) | 0x10;
	vcpu->arch.cpsr = 0;

	printk("in %s\n",__FUNCTION__);

	return vcpu;

free_vcpu:
	kmem_cache_free(kvm_vcpu_cache, vcpu);
out:
	return ERR_PTR(err);
}

int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	//in powperpc, only set timer
	return 0;
}

int kvm_arch_init(void *opaque)
{
	kvm_mmu_module_init();
	return 0;
}

static int __init kvm_arm_init(void)
{
	setup_vector();
	kvm_init(NULL, sizeof(struct kvm_vcpu), 0, THIS_MODULE);
	return 0;
}

//finish
void kvm_arch_destroy_vm(struct kvm *kvm)
{
}

void kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	//in powperpc, destroy the vcpu, free the resource
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
}

static void __exit kvm_arm_exit(void)
{
	printk("kvm: in kvm_arm_exit!!\n");
	restore_vector();
	kvm_exit();
}

void kvm_arch_exit(void)
{
}

//interrupt/exception
int kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu, unsigned int exception)
{
	if (exception ==  EXCP_FIQ)
		kvmarm_queue_async_exception(vcpu, ARM_INTERRUPT_FIQ);
	else if(exception == EXCP_IRQ)
		kvmarm_queue_async_exception(vcpu, ARM_INTERRUPT_IRQ);
	return 0;
}

struct kvm_stats_debugfs_item debugfs_entries[] = {
	{NULL}
}; 

static u32 kvmarm_modify_cpsr(struct kvm_vcpu *vcpu, int exception)
{
	u32 temp_cpsr = vcpu->arch.virtual_cpsr;
	temp_cpsr = temp_cpsr & 0xffffffe0; //clear mode bits
	u32 CPSR_E = (vcpu->arch.cp15.c1_sys & CP15_reg1_EEbit_MASK) << 9;

	switch (exception) {
	case ARM_INTERRUPT_UNDEFINED:
		temp_cpsr = temp_cpsr & CPSR_BIT57_MASK;
		temp_cpsr = temp_cpsr | PSR_I_BIT | CPSR_E | UND_MODE;
		break;
	case ARM_INTERRUPT_SOFTWARE:
		temp_cpsr = temp_cpsr & CPSR_BIT57_MASK;
		temp_cpsr = temp_cpsr | PSR_I_BIT | CPSR_E | SVC_MODE;
		break;
	case ARM_INTERRUPT_PREF_ABORT:
		temp_cpsr = temp_cpsr & CPSR_BIT57_MASK;
		temp_cpsr = temp_cpsr | PSR_I_BIT | CPSR_E | PSR_A_BIT | ABT_MODE;
		break;
	case ARM_INTERRUPT_DATA_ABORT:
		temp_cpsr = temp_cpsr & CPSR_BIT57_MASK;
		temp_cpsr = temp_cpsr | PSR_I_BIT | CPSR_E | PSR_A_BIT | ABT_MODE ;
		break;
	case ARM_INTERRUPT_IRQ:
		temp_cpsr = temp_cpsr & CPSR_BIT57_MASK;
		temp_cpsr = temp_cpsr | PSR_I_BIT | CPSR_E | PSR_A_BIT | IRQ_MODE;
		break;
	case ARM_INTERRUPT_FIQ:
		temp_cpsr = temp_cpsr & CPSR_BIT57_MASK;
		temp_cpsr = temp_cpsr | PSR_I_BIT | CPSR_E | PSR_A_BIT | PSR_F_BIT | FIQ_MODE;
		break;
	default:
		printk("NO SUCH EXCEPTION\n");
		KVM_BUG(1);
	}

	return temp_cpsr;
}   
/*
   1.move regs[15] to guest vector stub

   2.set 
   banked_spsr[6];
   banked_r14[6];

   3.sync/restore regs to/from virtual banked registers
 */  

static void kvmarm_deliver_exception(struct kvm_vcpu *vcpu, int inject_exception)
{
	u32 new_cpsr;
	u32* stack_addr;
	u32 bank_sp;
	u32 gfn;

	sync_condition_code(vcpu);

	switch (inject_exception) {	
	case ARM_INTERRUPT_UNDEFINED:
#if !defined(CONFIG_CPU_OPT) || !defined(CONFIG_INTR_OPT)
		store_banked_lr(vcpu, UND, vcpu->arch.regs[15]+4);
		store_banked_spsr(vcpu, UND, vcpu->arch.virtual_cpsr);
		new_cpsr = kvmarm_modify_cpsr(vcpu,ARM_INTERRUPT_UNDEFINED);
		vcpu->arch.regs[15] = 0xffff0380;
		break;
#else
		store_banked_lr(vcpu, UND, vcpu->arch.regs[15]);
		store_banked_spsr(vcpu, UND, vcpu->arch.virtual_cpsr);
		//store to stack
		bank_sp = load_banked_sp(vcpu, UND);
		gfn = vcpu->arch.mmu.gva_to_gpa(vcpu, bank_sp) >> 12;
		stack_addr = (gfn_to_hva(vcpu->kvm, gfn) | (bank_sp & 0xfff));
		//stack_addr = gfn_to_pfn(vcpu->kvm, gfn);
		*stack_addr = vcpu->arch.regs[0];
		*(stack_addr+1) = load_banked_lr(vcpu, UND);
		*(stack_addr+2) = load_banked_spsr(vcpu, UND);
		//change to svc
		vcpu->arch.regs[0] = bank_sp;
		new_cpsr = kvmarm_modify_cpsr(vcpu,ARM_INTERRUPT_SOFTWARE);
		if ((vcpu->arch.virtual_cpsr & 0x1f) == 0x10)
			vcpu->arch.regs[15] = 0xffff03c4;
		else if ((vcpu->arch.virtual_cpsr & 0x1f) == 0x13)
			vcpu->arch.regs[15] = 0xffff03d0;
		break;
#endif
	case ARM_INTERRUPT_SOFTWARE:
		kvm_profiling_count(&vcpu->stat.exp_inst);
		store_banked_lr(vcpu, SVC, vcpu->arch.regs[15]);
		store_banked_spsr(vcpu, SVC, vcpu->arch.virtual_cpsr);
		new_cpsr = kvmarm_modify_cpsr(vcpu,ARM_INTERRUPT_SOFTWARE);
		vcpu->arch.regs[15] = vcpu->arch.guest_swi_vector_addr;	
		break;
	case ARM_INTERRUPT_PREF_ABORT:
		kvm_profiling_count(&vcpu->stat.true_pabt_trap);
		sync_to_opt_regs(VIRT_C5C6, vcpu);
#if !defined(CONFIG_CPU_OPT) || !defined(CONFIG_INTR_OPT)
		store_banked_lr(vcpu, ABORT, vcpu->arch.regs[15]+4);
		store_banked_spsr(vcpu, ABORT, vcpu->arch.virtual_cpsr);
		new_cpsr = kvmarm_modify_cpsr(vcpu,ARM_INTERRUPT_PREF_ABORT);
		vcpu->arch.regs[15] = 0xffff0300;
		break;
#else
		store_banked_lr(vcpu, ABORT, vcpu->arch.regs[15]);
		store_banked_spsr(vcpu, ABORT, vcpu->arch.virtual_cpsr);

		//store to stack
		bank_sp = load_banked_sp(vcpu, ABORT);
		gfn = vcpu->arch.mmu.gva_to_gpa(vcpu, bank_sp) >> 12;
		stack_addr = (gfn_to_hva(vcpu->kvm, gfn) | (bank_sp & 0xfff));
		//stack_addr = gfn_to_pfn(vcpu->kvm, gfn);
		*stack_addr = vcpu->arch.regs[0];
		*(stack_addr+1) = load_banked_lr(vcpu, ABORT);
		*(stack_addr+2) = load_banked_spsr(vcpu, ABORT);
		//change to svc
		vcpu->arch.regs[0] = bank_sp;
		new_cpsr = kvmarm_modify_cpsr(vcpu,ARM_INTERRUPT_SOFTWARE);
		if ((vcpu->arch.virtual_cpsr & 0x1f) == 0x10)
			vcpu->arch.regs[15] = 0xffff0344;
		else if ((vcpu->arch.virtual_cpsr & 0x1f) == 0x13)
			vcpu->arch.regs[15] = 0xffff0350;
		break;
#endif
	case ARM_INTERRUPT_DATA_ABORT:
		kvm_profiling_count(&vcpu->stat.true_dabt_trap);
		sync_to_opt_regs(VIRT_C5C6, vcpu);
#if !defined(CONFIG_CPU_OPT) || !defined(CONFIG_INTR_OPT)
		store_banked_lr(vcpu, ABORT, vcpu->arch.regs[15]+8);
		store_banked_spsr(vcpu, ABORT, vcpu->arch.virtual_cpsr);
		new_cpsr = kvmarm_modify_cpsr(vcpu,ARM_INTERRUPT_DATA_ABORT);
		vcpu->arch.regs[15] = 0xffff0280;
		break;
#else
		store_banked_lr(vcpu, ABORT, vcpu->arch.regs[15]);
		store_banked_spsr(vcpu, ABORT, vcpu->arch.virtual_cpsr);
		//store to stack
		bank_sp = load_banked_sp(vcpu, ABORT);
		gfn = vcpu->arch.mmu.gva_to_gpa(vcpu, bank_sp) >> 12;
		stack_addr = (gfn_to_hva(vcpu->kvm, gfn) | (bank_sp & 0xfff));
		//stack_addr = gfn_to_pfn(vcpu->kvm, gfn);
		*stack_addr = vcpu->arch.regs[0];
		*(stack_addr+1) = load_banked_lr(vcpu, ABORT);
		*(stack_addr+2) = load_banked_spsr(vcpu, ABORT);
		//change to svc
		vcpu->arch.regs[0] = bank_sp;
		new_cpsr = kvmarm_modify_cpsr(vcpu,ARM_INTERRUPT_SOFTWARE);
		if ((vcpu->arch.virtual_cpsr & 0x1f) == 0x10)
			vcpu->arch.regs[15] = 0xffff02c4;
		else if ((vcpu->arch.virtual_cpsr & 0x1f) == 0x13)
			vcpu->arch.regs[15] = 0xffff02d0;
		break;
#endif
	case ARM_INTERRUPT_IRQ:
#if !defined(CONFIG_CPU_OPT) || !defined(CONFIG_INTR_OPT)
		store_banked_lr(vcpu, IRQ, vcpu->arch.regs[15] + 4);
		store_banked_spsr(vcpu, IRQ, vcpu->arch.virtual_cpsr);
		new_cpsr = kvmarm_modify_cpsr(vcpu,ARM_INTERRUPT_IRQ);
		vcpu->arch.regs[15] = 0xffff0200;
		break;
#else
		store_banked_lr(vcpu, IRQ, vcpu->arch.regs[15]);
		store_banked_spsr(vcpu, IRQ, vcpu->arch.virtual_cpsr);
		//store to stack
		bank_sp = load_banked_sp(vcpu, IRQ);
		gfn = vcpu->arch.mmu.gva_to_gpa(vcpu, bank_sp) >> 12;
		stack_addr = (gfn_to_hva(vcpu->kvm, gfn) | (bank_sp & 0xfff));
		//stack_addr = gfn_to_pfn(vcpu->kvm, gfn);
		*stack_addr = vcpu->arch.regs[0];
		*(stack_addr+1) = load_banked_lr(vcpu, IRQ);
		*(stack_addr+2) = load_banked_spsr(vcpu, IRQ);
		//change to svc
		vcpu->arch.regs[0] = bank_sp;
		new_cpsr = kvmarm_modify_cpsr(vcpu,ARM_INTERRUPT_SOFTWARE);
		if ((vcpu->arch.virtual_cpsr & 0x1f) == 0x10)
			vcpu->arch.regs[15] = 0xffff0244;
		else if ((vcpu->arch.virtual_cpsr & 0x1f) == 0x13)
			vcpu->arch.regs[15] = 0xffff0250;
		break;
#endif
	case ARM_INTERRUPT_FIQ:
		store_banked_lr(vcpu, FIQ, vcpu->arch.regs[15] + 4);
		store_banked_spsr(vcpu, FIQ, vcpu->arch.virtual_cpsr);
		new_cpsr = kvmarm_modify_cpsr(vcpu,ARM_INTERRUPT_FIQ);
		vcpu->arch.regs[15] = 0xffff0400;
		break;
	default:
		printk("NO SUCH EXCEPTION\n");
		KVM_BUG(1); 
	}	
	//sync to current and sync from banked
	modify_cpsr(vcpu, new_cpsr);
}

/* Check if we are ready to deliver the interrupt 
   not handling imprecise abort
 */
static int kvmarm_can_deliver_exception(struct kvm_vcpu *vcpu, int exception)
{
	int r;
	switch (exception) {
	case 0:
		r = 0;
		break;
	case ARM_INTERRUPT_UNDEFINED:
		r = 1;
		break;
	case ARM_INTERRUPT_SOFTWARE:
		r = 1;
		break;
	case ARM_INTERRUPT_PREF_ABORT:
		r = 1;
		break;		
	case ARM_INTERRUPT_DATA_ABORT:	
		r = 1;
		break;
	case ARM_INTERRUPT_IRQ:
		r = !(vcpu->arch.virtual_cpsr & PSR_I_BIT);
		break;
	case ARM_INTERRUPT_FIQ:
		r = !(vcpu->arch.virtual_cpsr & PSR_F_BIT);
	default:
		printk("NO SUCH EXCEPTION\n");
		KVM_BUG(1);
	}
	return r;
}

//kvmarm_deliver_exception¤§«á
void kvmarm_check_and_deliver_exceptions(struct kvm_vcpu *vcpu, int num)
{
	unsigned int exception; 
	int mode = 0;

	if (vcpu->arch.pending_sync_exceptions) {
		exception = vcpu->arch.pending_sync_exceptions;
		mode = 1;
	} else if (vcpu->arch.pending_async_exceptions) {
		exception = vcpu->arch.pending_async_exceptions;
		mode = 2;
	}

	if (kvmarm_can_deliver_exception(vcpu, exception)) {
		if (mode == 1) {
			kvmarm_clear_sync_exception(vcpu, exception);
		} else if (mode == 2) {
			kvmarm_clear_async_exception(vcpu, exception);
		}
		kvmarm_deliver_exception(vcpu, exception);
	}
}

//helper
//kvm
void kvm_arch_flush_shadow(struct kvm *kvm)
{
	kvm_reload_remote_mmus(kvm);
}

int kvm_arch_hardware_enable(void *garbage)
{
	return 0;
}

void kvm_arch_hardware_disable(void *garbage)
{
}

int kvm_arch_hardware_setup(void)
{
	return 0;
}

void kvm_arch_hardware_unsetup(void)
{
}

void kvm_arch_check_processor_compat(void *rtn)
{
}

int kvm_arch_vcpu_runnable(struct kvm_vcpu *v)
{
	return 0;
}

int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
		struct kvm_guest_debug *dbg)
{
	return -EINVAL;
}

void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	if (cpu != vcpu->cpu) {
		vcpu->cpu = cpu;
	}
}

void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu)
{
}

int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
		struct kvm_mp_state *mp_state)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
		struct kvm_mp_state *mp_state)
{
	return -EINVAL;
}

int kvm_cpu_has_interrupt(struct kvm_vcpu *v)
{
	return (v->arch.pending_async_exceptions) || (v->arch.pending_sync_exceptions);
}

int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu)
{
	return 0;
}

int kvm_vm_ioctl_get_dirty_log(struct kvm *kvm, struct kvm_dirty_log *log)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_debug_guest(struct kvm_vcpu *vcpu,
		struct kvm_debug_guest *dbg)
{

	return 0;
}

gfn_t unalias_gfn(struct kvm *kvm, gfn_t gfn)
{
	return gfn;
}


int kvm_arch_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	/* do real check here */
	if(vcpu->arch.virtual_cpsr & 0x60)
		return 0;
	else 
		return 1; 
}

void kvm_arch_sync_events(struct kvm *kvm)
{
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	int i;
	regs->cpsr = vcpu->arch.virtual_cpsr;
	regs->spsr = vcpu->arch.spsr;
	regs->cp15.c5_insn = vcpu->arch.cp15.c5_insn;
	regs->cp15.c5_data = vcpu->arch.cp15.c5_data;
	regs->cp15.c6_insn = vcpu->arch.cp15.c6_insn;
	regs->cp15.c6_data = vcpu->arch.cp15.c6_data;
	for (i = 0; i < 16; i++)
		regs->gpr[i] = vcpu->arch.regs[i];

	return 0;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	int i;

	vcpu->arch.virtual_cpsr = regs->cpsr;
	vcpu->arch.spsr = regs->spsr;
	/*****synchronize CP15*******/
	vcpu->arch.cp15.c0_cpuid = regs->cp15.c0_cpuid;
	vcpu->arch.cp15.c0_cachetype = read_cpuid_cachetype();
	for (i = 0; i < 16; i++)
		vcpu->arch.cp15.c0_ccsid[i] = regs->cp15.c0_ccsid[i];
	vcpu->arch.cp15.c0_clid = regs->cp15.c0_clid;
	vcpu->arch.cp15.c0_cssel = regs->cp15.c0_cssel;
	for (i = 0; i < 8; i++)
		vcpu->arch.cp15.c0_c1[i] = regs->cp15.c0_c1[i];
	for (i = 0; i < 8; i++)
		vcpu->arch.cp15.c0_c2[i] = regs->cp15.c0_c2[i];
	vcpu->arch.cp15.c1_sys = regs->cp15.c1_sys;
	vcpu->arch.cp15.c1_coproc = regs->cp15.c1_coproc;
	vcpu->arch.cp15.c1_xscaleauxcr = regs->cp15.c1_xscaleauxcr;
	vcpu->arch.cp15.c2_base0 = regs->cp15.c2_base0;
	vcpu->arch.cp15.c2_base1 = regs->cp15.c2_base1;
	vcpu->arch.cp15.c2_control = regs->cp15.c2_control;
	vcpu->arch.cp15.c2_mask = regs->cp15.c2_mask;
	vcpu->arch.cp15.c2_base_mask = regs->cp15.c2_base_mask;
	vcpu->arch.cp15.c2_data = regs->cp15.c2_data;
	vcpu->arch.cp15.c2_insn = regs->cp15.c2_insn;
	vcpu->arch.cp15.c3 = regs->cp15.c3;
	vcpu->arch.cp15.c5_insn = regs->cp15.c5_insn;
	vcpu->arch.cp15.c5_data = regs->cp15.c5_data;
	for (i = 0; i < 8; i++)
		vcpu->arch.cp15.c6_region[i] = regs->cp15.c6_region[i];
	vcpu->arch.cp15.c6_insn = regs->cp15.c6_insn;
	vcpu->arch.cp15.c6_data = regs->cp15.c6_data;
	vcpu->arch.cp15.c9_insn = regs->cp15.c9_insn;
	vcpu->arch.cp15.c9_data = regs->cp15.c9_data;
	vcpu->arch.cp15.c13_fcse = regs->cp15.c13_fcse;
	vcpu->arch.cp15.c13_context = regs->cp15.c13_context;
	vcpu->arch.cp15.c13_tls1 = regs->cp15.c13_tls1;
	vcpu->arch.cp15.c13_tls2 = regs->cp15.c13_tls2;
	vcpu->arch.cp15.c13_tls3 = regs->cp15.c13_tls3;
	vcpu->arch.cp15.c15_cpar = regs->cp15.c15_cpar;
	vcpu->arch.cp15.c15_ticonfig = regs->cp15.c15_ticonfig;
	vcpu->arch.cp15.c15_i_max = regs->cp15.c15_i_max;
	vcpu->arch.cp15.c15_i_min = regs->cp15.c15_i_min;
	vcpu->arch.cp15.c15_threadid = regs->cp15.c15_threadid;

	for (i = 0; i < 16; i++)
		vcpu->arch.regs[i] = regs->gpr[i];
	memset(&vcpu->stat,0,sizeof(struct kvm_vcpu_stat));
	return 0;
}

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
		struct kvm_sregs *sregs)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
		struct kvm_sregs *sregs)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
		struct kvm_translation *tr)
{
	return 0;
}

//qemu
int kvm_arch_set_memory_region(struct kvm *kvm,
		struct kvm_userspace_memory_region *mem,
		struct kvm_memory_slot old,
		int user_alloc)
{
	int npages = mem->memory_size >> PAGE_SHIFT;
	struct kvm_memory_slot *memslot = &kvm->memslots->memslots[mem->slot];

	/*To keep backward compatibility with older userspace,
	 *x86 needs to hanlde !user_alloc case.
	 */
	if (!user_alloc) {
		BUG();
	}

	if (!kvm->arch.n_requested_mmu_pages) {
		unsigned int nr_mmu_pages = kvm_mmu_calculate_mmu_pages(kvm);
		kvm_mmu_change_mmu_pages(kvm, nr_mmu_pages);
	}

	return 0;
}

static void kvmarm_complete_mmio_load(struct kvm_vcpu *vcpu,struct kvm_run *run)
{
	u32 *gpr;
	u8 *data;
	int i;
	u32 value;
	u32 tmp_cpsr;
	u32 mode = TRANSFER_MODEBITS(vcpu->arch.virtual_cpsr & MODE_MASK);

	if (vcpu->arch.is_mls) {
		data = run->mmio.data;
		if (vcpu->arch.load_style == 1) {
			//LDM(1)
			for (i = 0; i <= 15; i++) {
				if (test_bit(i, &vcpu->arch.mls_regs)) {
					value = *(u32 *)data;
					vcpu->arch.regs[i] = value;
					data = data+4;
				}
			}
		} else if (vcpu->arch.load_style == 2) {
			//LDM(2)
			for (i = 0; i <= 7; i++) {
				if (test_bit(i, &vcpu->arch.mls_regs)) {
					value = *(u32 *)data;
					vcpu->arch.regs[i] =value;
					data =data +4;
				}
			}
			for (i = 8; i <= 12; i++) {
				if (test_bit(i,&vcpu->arch.mls_regs)) {
					value = *(u32 *)data;
					vcpu->arch.usr_regs[i-8] =value;
					data =data +4;
				}
			}
			if (test_bit(13, &vcpu->arch.mls_regs)) {
				value = *(u32 *)data;
				store_banked_sp(vcpu, USR, value);
				data =data +4;
			}
			if (test_bit(14, &vcpu->arch.mls_regs)) {
				value = *(u32 *)data;
				store_banked_lr(vcpu, USR, value);
				data =data +4;
			}
		} else if (vcpu->arch.load_style == 3) {
			//LDM(3)
			for (i = 0; i <= 15; i++) {
				//assume the target regiter is PC
				if (test_bit(i, &vcpu->arch.mls_regs)) {
					value = *(u32 *)data;
					//printk("i = %x value = %x\n",i,value);
					vcpu->arch.regs[i] = value;
					data = data+4;
				}
			}
			tmp_cpsr = load_banked_spsr(vcpu, mode);
			modify_cpsr(vcpu, tmp_cpsr);
		}
	} else {
		gpr = &vcpu->arch.regs[vcpu->arch.io_gpr];

		if (run->mmio.len > sizeof(*gpr)) {
			printk(KERN_ERR "bad MMIO length: %d\n", run->mmio.len);
			return;
		}

		switch (run->mmio.len) {
		case 4:
			*gpr = *(u32 *)run->mmio.data;
			 break;
		case 2:
			*gpr = *(u16 *)run->mmio.data;
			break;
		case 1:
			*gpr = *(u8 *)run->mmio.data;
			break;
		}
		if (vcpu->arch.signed_flag == 1) {
			if (*gpr >=0x1000)
				*gpr = 0xffff0000+*gpr;
			vcpu->arch.signed_flag =0;
		}
	}
}

//¦bkvm_vcpu_ioctl_interrupt ¤§«á
long kvm_arch_vcpu_ioctl(struct file *filp,
		unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r;
	unsigned int exception;

	switch (ioctl) {
	case KVM_INTERRUPT:
		r = -EFAULT;
		if (copy_from_user(&exception, argp, sizeof(exception)))
			goto out;
		r = kvm_vcpu_ioctl_interrupt(vcpu, exception);
		break;
	default:
		r = -EINVAL;
	}

out:
	return r;
}

long kvm_arch_vm_ioctl(struct file *filp,
		unsigned int ioctl, unsigned long arg)
{
	long r;

	switch (ioctl) {
	default:
		r = -EINVAL;
	}

	return r;
}

int kvm_dev_ioctl_check_extension(long ext)
{
	int r;

	switch (ext) {
	case KVM_CAP_USER_MEMORY:
		r = 1;
		break;
	case KVM_CAP_COALESCED_MMIO:
		r = KVM_COALESCED_MMIO_PAGE_OFFSET;
		break;
	default:
		r = 0;
		break;
	}
	return 1;
}

long kvm_arch_dev_ioctl(struct file *filp,
		unsigned int ioctl, unsigned long arg)
{
	return -EINVAL;
}

int kvm_arch_prepare_memory_region(struct kvm *kvm,
		struct kvm_memory_slot *memslot,
		struct kvm_memory_slot old,
		struct kvm_userspace_memory_region *mem,
		int user_alloc)
{
	return 0;
}

void kvm_arch_commit_memory_region(struct kvm *kvm,
		struct kvm_userspace_memory_region *mem,
		struct kvm_memory_slot old,
		int user_alloc)
{
	return;
}

int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	kvm_mmu_setup(vcpu);

	return 0;
}

//run
//¦bkvmarm_complete_mmio_load¤§«á
int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int r;
	sigset_t sigsaved;  

	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &vcpu->sigset, &sigsaved);

	if (vcpu->mmio_needed) {
		if (!vcpu->mmio_is_write)
			kvmarm_complete_mmio_load(vcpu, run);
		vcpu->mmio_needed = 0;
	}

	kvmarm_check_and_deliver_exceptions(vcpu,0);

	sync_to_opt_regs(VIRT_CPSR, vcpu);
	sync_to_opt_regs(VIRT_SVC_SPSR, vcpu);
	//load mmu
	r = kvm_mmu_reload(vcpu);
	if (unlikely(r))
		goto out;

	local_irq_disable();

	r = __kvmarm_vcpu_run(vcpu);

	local_irq_enable();

	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &sigsaved, NULL);

out:
	return r;
}
module_init(kvm_arm_init)
module_exit(kvm_arm_exit)
