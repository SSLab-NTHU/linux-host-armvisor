/**
 *  @vsoft_trap.c
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

#include <linux/kvm.h>
#include <linux/errno.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/kvm_host.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_para.h>
#include <asm/cacheflush.h>
#include "mmu.h"
#include "vsoft_vcpu.h"
#include "emulate_arm.h"
#include "profile.h"

#define SWI_EMU_TRAP		0x190
#define SWI_FREE_PTE		0x207
#define SWI_WRITE_PTE		0x205
#define SWI_CORRECT_TIMER	0x0
#define SWI_SET_VECTOR_ADDR	0x196

extern struct kvm_vcpu *kvm_vcpu_pointer;
unsigned long *vector_store;
unsigned long *stub_store;

#ifdef CONFIG_PROFILE_MODEL
static int handle_profile_call(u32 swi_num, struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.swi_num == 0x200) {
		profile_dump_count2(vcpu);
		profile_dump_pc(vcpu);
		return 1;
	} else if (vcpu->arch.swi_num == 0x201) {
		//initial profile
		free_pc_record_all(vcpu);
		memset(&vcpu->stat, 0, sizeof(struct kvm_vcpu_stat));
		vcpu->stat.asm_info = 0xffff1e00;
		memset(vcpu->stat.asm_info, 0, sizeof(struct asm_profiling_info));
		return 1;
	} else if (vcpu->arch.swi_num == 0x202) { 
		//reset profiling cpu, mem overhead (time)
		return 1;
	} else if (vcpu->arch.swi_num == 0x203) {
		//retrieve cpu, mem overhead
		return 1;
	}
	return 0;
}
#else
#define handle_profile_call(swi_num, vcpu) 0
#endif

/**
 * @brief trap handler, handle for undefine case
 * 
 * In this case, include real undefine instructions and "privilged and sensitive instructions"
 * If it's "privilged and sensitive" instruction, that's what we should emulate. We will call emulate 
 * function to emulate it.
 * 
 * If it's real undefine instructions. We will call KVM_BUG let it treat as undefine instructions.
 *
 * @param *vcpu structure for virtual_cpu
 */
static void kvmarm_handle_undefine(struct kvm_vcpu *vcpu)
{
	u32 mode;
	mode = TRANSFER_MODEBITS(vcpu->arch.virtual_cpsr & MODE_MASK);
	if (mode == USR) {
		printk("INTERRUPT_UNDEFINED \n");
		KVM_BUG(0);
	} else {		
		kvmarm_emulate_instruction(vcpu, NON_CRITICAL_INST);
	}
}

void kvm_let_guest_timer_more_accurat(struct kvm_vcpu *vcpu)
{
	gpa_t gpa = vcpu->arch.mmu.gva_to_gpa(vcpu, vcpu->arch.regs[0]);
	gfn_t gfn = gpa >> 12; 
	u32 hva_tmp = gfn_to_hva(vcpu->kvm, gfn);
	struct timeval *tv = hva_tmp | (gpa & ~PAGE_MASK);
	extern struct timezone sys_tz;

	do_gettimeofday(tv);

	if (vcpu->arch.regs[1] != 0) {
		gpa = vcpu->arch.mmu.gva_to_gpa(vcpu, vcpu->arch.regs[1]);
		gfn = gpa >> 12; 
		hva_tmp = gfn_to_hva(vcpu->kvm, gfn);
		struct timezone *tz = hva_tmp | (gpa & ~PAGE_MASK);
		*tz = sys_tz; 
	}   
}

/**
  * @brief trap handler, handle for software interrupt case
  * 
  * In this case, we will handle all software interrupt in this function.
  * There are 6 cases in this handler.
  * 
  * @param *vcpu virtual cpu info from guest 
  * 
  * @return break_flag break_or_not flag
  */
int kvmarm_handle_swi(struct kvm_vcpu *vcpu)
{
	int break_flag = 0;	
	if (vcpu->arch.swi_num == SWI_EMU_TRAP) {
		vcpu->arch.is_mmio_inst = 0;
		kvmarm_emulate_instruction(vcpu, CRITICAL_INST);
#ifdef CONFIG_MEM_OPT				
	} else if (vcpu->arch.swi_num == SWI_FREE_PTE) {
		kvm_profiling_count(&vcpu->stat.pv_free_pte);
		kvm_free_pt_pv(vcpu);
	} else if (vcpu->arch.swi_num == SWI_WRITE_PTE) {
		kvm_profiling_count(&vcpu->stat.pv_write_pte);
		kvm_fill_pt_pv(vcpu);
#endif				
	} else if (vcpu->arch.swi_num == SWI_CORRECT_TIMER && vcpu->arch.regs[7] == 78) {
		kvm_let_guest_timer_more_accurat(vcpu);
	} else if (vcpu->arch.swi_num == SWI_SET_VECTOR_ADDR) {
		printk("------> SWI ADDR = %x\n", vcpu->arch.regs[0]);
		vcpu->arch.guest_swi_vector_addr = vcpu->arch.regs[0];
		sync_to_opt_regs(VECTOR_SWI, vcpu);
	} else {
		if(handle_profile_call(exit_nr, vcpu)) {
			break_flag = 1;
			goto out;
		}
		kvmarm_queue_sync_exception(vcpu,ARM_INTERRUPT_SOFTWARE);
	}	
out:
	return break_flag;
}

/**
 * @brief kvmarm_handle_exit is the first function to handle the trap from guest OS in .c codes.
 *
 * @param *vcpu a structure contains the value of cpu registers in guest
 * @param exit_nr save the exit reason number
 * 
 * @return Indicate which OS should be resumed 
 */
int kvmarm_handle_exit(struct kvm_vcpu *vcpu, unsigned int exit_nr)
{
	int resume_os = RESUME_GUEST;

	vcpu->run->exit_reason = 0;

	sync_from_opt_regs(VIRT_CPSR, vcpu);
	sync_from_opt_regs(VIRT_SVC_SPSR, vcpu);

	local_irq_enable();

	kvm_profiling_count(&vcpu->stat.handle_exit);
	switch (exit_nr) {
	case ARM_INTERRUPT_UNDEFINED:
		kvmarm_handle_undefine(vcpu);
		break;
	case ARM_INTERRUPT_SOFTWARE:
		kvmarm_handle_swi(vcpu);		
		break;
	case ARM_INTERRUPT_PREF_ABORT:
		kvm_profiling_count(&vcpu->stat.pabt_exits);
		resume_os = kvm_mmu_page_fault(vcpu, vcpu->arch.regs[15], exit_nr);
		break;
	case ARM_INTERRUPT_DATA_ABORT:
		kvm_profiling_count(&vcpu->stat.dabt_exits);
		resume_os = kvm_mmu_page_fault(vcpu, vcpu->arch.guest_c6_data, exit_nr);
		break;
	case ARM_INTERRUPT_IRQ:
		kvm_profiling_count(&vcpu->stat.int_trap);
		if (need_resched())
                        cond_resched();
		break;
	case ARM_INTERRUPT_FIQ:
		printk("NEED INJECT FIQ\n");	
		KVM_BUG(0);
		break;
	default:
		printk(KERN_EMERG "exit_nr %d,pc:%x\n", exit_nr,vcpu->arch.regs[15]);
		KVM_BUG(0);	
		break;
	}
	local_irq_disable();

	/* TODO : response time turned long when return to user space for hidden faults*/

	if (exit_nr == ARM_INTERRUPT_IRQ) {
		vcpu->run->exit_reason = KVM_EXIT_NEED_INJECT;
                        resume_os = RESUME_HOST;
	}

	if (resume_os == RESUME_GUEST) {
		kvmarm_check_and_deliver_exceptions(vcpu, 1);
		sync_to_opt_regs(VIRT_CPSR, vcpu);
		sync_to_opt_regs(VIRT_SVC_SPSR, vcpu);
	}

	return resume_os;		
}

int setup_vector(void)
{

	//kvm vectors
	unsigned long vectors = CONFIG_VECTORS_BASE;
	extern char __kvm_vectors_start[], __kvm_vectors_end[];

	//kvm stub handler
	extern char __kvm_stubs_start[], __kvm_stubs_end[];

	//enter guest_run code
	extern char guest_run_end[];
	extern char guest_run_start[]; 

	unsigned long relocate_kvm_vector = 0xffff1000; 
	u32 kvm_stub_end_addr = relocate_kvm_vector + (__kvm_stubs_end-__kvm_stubs_start);
	unsigned long relocate_guest_run = 0xffff1600; 
	u32 kvm_guest_run_addr = relocate_guest_run + (guest_run_end - guest_run_start);
	unsigned long* tmp_sp_addr = 0xffff1800; 

	extern u32 *vcpu_flag_addr;

	kvm_vcpu_pointer = NULL;


	*vcpu_flag_addr = 0;

	*tmp_sp_addr = 0xffff1840;

	vector_store = (unsigned long*) kzalloc(__kvm_vectors_end - __kvm_vectors_start, GFP_KERNEL);
	memcpy((void *)vector_store, vectors, __kvm_vectors_end - __kvm_vectors_start);
	memcpy((void *)vectors, __kvm_vectors_start, __kvm_vectors_end - __kvm_vectors_start);

	stub_store = (unsigned long*) kzalloc(__kvm_stubs_end - __kvm_stubs_start, GFP_KERNEL);
	memcpy((void *)stub_store, relocate_kvm_vector, __kvm_stubs_end - __kvm_stubs_start);
	memcpy((void *)relocate_kvm_vector, __kvm_stubs_start, __kvm_stubs_end - __kvm_stubs_start);

	memcpy((void *)relocate_guest_run, guest_run_start, guest_run_end - guest_run_start);

	printk("----> kvm_start: %x\tkvm_end: %x\n", (unsigned int)__kvm_vectors_start, (unsigned int)__kvm_vectors_end);
	printk("----> guest_run_start : %x\tkvm_guest_run_end_addr : %x\n", (unsigned int)relocate_guest_run, (unsigned int)kvm_guest_run_addr);
	printk("----> kvm_stub_end_addr : %x\n", (unsigned int)kvm_stub_end_addr);
	if (kvm_guest_run_addr >= 0xffff1800)
		BUG();

	return 0;
}

void restore_vector(void)
{
	extern char __kvm_vectors_start[], __kvm_vectors_end[];
	extern char __kvm_stubs_start[], __kvm_stubs_end[];

	printk("kvm: in kvmarm_realview_exit!!\n");
	unsigned long vectors = CONFIG_VECTORS_BASE;
	memcpy((void *)vectors, vector_store, __kvm_vectors_end - __kvm_vectors_start);
	kfree(vector_store);
	kfree(stub_store);
}

#ifdef CONFIG_CPU_OPT
void sync_to_opt_regs(enum regs_type type, struct kvm_vcpu *vcpu)
{

	kvm_profiling_count(&vcpu->stat.sync_to_opt);
	switch (type) {
	case VIRT_CPSR:
		kvm_virt_regs->cpsr = vcpu->arch.virtual_cpsr;
		break;
	case VIRT_SVC_SP:
		kvm_virt_regs->svc_sp = vcpu->arch.banked_r13[SVC];
		break;
	case VIRT_SVC_LR:
		kvm_virt_regs->svc_lr = vcpu->arch.banked_r14[SVC];
		break;
	case VIRT_SVC_SPSR:
		kvm_virt_regs->svc_spsr = vcpu->arch.banked_spsr[SVC];
		break;
	case VIRT_USR_SP:
		kvm_virt_regs->usr_sp = vcpu->arch.banked_r13[USR];
		break;
	case VIRT_USR_LR:
		kvm_virt_regs->usr_lr = vcpu->arch.banked_r14[USR];
		break;
	case VIRT_C5C6:
		kvm_virt_regs->c5_data = vcpu->arch.cp15.c5_data;
		kvm_virt_regs->c6_data = vcpu->arch.cp15.c6_data;
		break;
	case VECTOR_SWI:
		kvm_virt_regs->vector_swi = vcpu->arch.guest_swi_vector_addr;
		break;
	default:
		KVM_BUG(0);
	}
}

void sync_from_opt_regs(enum regs_type type, struct kvm_vcpu *vcpu)
{
	kvm_profiling_count(&vcpu->stat.sync_from_opt);
	switch(type) {
	case VIRT_CPSR:
		vcpu->arch.virtual_cpsr = kvm_virt_regs->cpsr;
		sync_condition_code(vcpu);
		break;
	case VIRT_SVC_SPSR:
		vcpu->arch.banked_spsr[SVC] = kvm_virt_regs->svc_spsr;
		break;
	case VIRT_SVC_SP:
		vcpu->arch.banked_r13[SVC] = kvm_virt_regs->svc_sp;
		break;
	case VIRT_SVC_LR:
		vcpu->arch.banked_r14[SVC] = kvm_virt_regs->svc_lr;
		break;
	case VIRT_USR_SP:
		vcpu->arch.banked_r13[USR] = kvm_virt_regs->usr_sp;
		break;
	case VIRT_USR_LR:
		vcpu->arch.banked_r14[USR] = kvm_virt_regs->usr_lr;
		break;
	default:
		KVM_BUG(0);
	}
}
#endif
