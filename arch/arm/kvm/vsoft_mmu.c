/**
 *  @vsoft_mmu.c
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

#include <linux/highmem.h>
#include <linux/slab.h>
#include <asm/tlbflush.h>
#include <asm/kvm_arm.h>
#include "mmu.h"
#include "vsoft_mmu.h"
#include "vsoft_mmu_hpte.h"
#include "vsoft_vcpu.h"
#include "emulate_arm.h"

/*
 * c15_reset_mmu
 * @vcpu
 */
void vsoft_c15_reset_mmu(struct kvm_vcpu *vcpu) 
{
	reset_vector_table(vcpu);
	kvm_mmu_reset_context(vcpu);
	kvm_mmu_reload(vcpu);
}

/*
 * c15_reset_ttbr0 
 * @vcpu
 */
void vsoft_c15_reset_ttbr0(struct kvm_vcpu *vcpu) 
{
	if(is_paging(vcpu))
		kvm_mmu_load(vcpu);
}

/*
 * c15_reset_domain
 * @vcpu
 * @guest_domain: the guest wants to set the domain
 * 
 * This function emulates the behavior that the guest OS resets domain.
 * We assume that both the HOS and GOS only use 3 domains respectively.
 */
void vsoft_c15_reset_domain(struct kvm_vcpu *vcpu, u32 guest_domain)
{
	u32 host_domain = 0;
	u32 hw_domain = 0;
	struct thread_info *thread;
	int mode;
	
	__asm__ __volatile__(
		"mrc p15, #0, %0, c3, c0, #0"
		:"=r"(host_domain)
	);
	host_domain &= 0x3f;

	guest_domain = (guest_domain << 6);

	mode = get_guest_mode(vcpu);
	if(mode == KERNEL) {
		/*
		 * TODO: vector domain = Manager for kernel mode?
		 */
		guest_domain |= (DOMAIN_CLIENT) << (2 * DOMAIN_GUEST_KERNEL)
			 | (DOMAIN_MANAGER) << (2 * DOMAIN_GUEST_VECTOR);
	} else {
		guest_domain |= (DOMAIN_CLIENT) << (2 * DOMAIN_GUEST_KERNEL)
			 | (DOMAIN_MANAGER) << (2 * DOMAIN_GUEST_VECTOR);
	}
	
	hw_domain = guest_domain | host_domain;

	__asm__ __volatile__(
		"mcr p15, #0, %0, c3, c0, #0"
		:
		:"r"(hw_domain)
	);
	isb();

	thread = current_thread_info();
	thread->cpu_domain = hw_domain;
}

/*
 * vsoft_c15_context - set the handling function of partial CP15 instructions
 * @vcpu
 * 
 * We think there should be some differnece betwwen software solutions and 
 * hardware solutions when emulating the CP15 co-processor instructions.
 */
void vsoft_c15_context(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;
	context->c15_reset_mmu = vsoft_c15_reset_mmu;
	context->c15_reset_ttbr0 = vsoft_c15_reset_ttbr0;
	context->c15_reset_domain = vsoft_c15_reset_domain;
	return;
}

/*
 * kvm_mmu_page_fault - the entry of handling an abort
 * @vcpu
 * @addr: the requested address
 * @exit_reason: the reason that guest OS exits its execution context
 * 
 * This function would call the abort handling function ans do the related
 * operation according to the return value.
 */
int vsoft_mmu_page_fault(struct kvm_vcpu *vcpu, gva_t addr, u32 exit_reason)
{
	enum mmu_reason mmu_r;

	int r = mmu_topup_memory_caches(vcpu);
	if(r) KVM_MMU_BUG();

	mmu_r = vcpu->arch.mmu.handle_fault(vcpu, addr, exit_reason);

	switch(mmu_r){
	case MMU_OK:
		break;
	case MMU_INJECT_FAULT:
		vcpu->arch.cp15.c5_insn = vcpu->arch.guest_c5_insn;
		vcpu->arch.cp15.c5_data = vcpu->arch.guest_c5_data;
		vcpu->arch.cp15.c6_data = vcpu->arch.guest_c6_data;
		kvmarm_queue_sync_exception(vcpu, exit_reason);
		break;
	case MMU_MMIO:
		vcpu->arch.paddr_accessed = vcpu->arch.mmu.mmio_addr; 
		vcpu->run->exit_reason = KVM_EXIT_MMIO;
		vcpu->arch.is_mmio_inst = 1;
		kvmarm_emulate_instruction(vcpu, CRITICAL_INST);
		return RESUME_HOST;
	case MMU_SPT:
		vcpu->arch.is_mmio_inst = 0; 
		kvmarm_emulate_instruction(vcpu, CRITICAL_INST);
		break;
	default:
		KVM_MMU_BUG();
		break;
	}
	return RESUME_GUEST;
}

/*
 * hpa_to_hpa - input HVA then get HPA
 * @root: the host page table
 * @addr
 */
static hpa_t hva_to_hpa(u32 *root, u32 addr)
{
	int index;
	hpa_t hpa;
	u32 pde;
	u32 pte;
	u32 *pt;

	index = ROOT_INDEX(addr);
	pde = root[index];

	pt = GET_PT_HVA(pde);
	index = PT_INDEX(addr);

	pte = pt[index];
	hpa = ((pte) & PAGE_MASK) | (addr & (~PAGE_MASK) );
	return hpa;
}   

/*
 * init_kvm_vector - intialize the self-defined KVM vector
 * @vcpu
 * 
 * The hypervisor would intercpet the GOS traps, so we design a vector table.
 * We create two page: one for storing the KVM vector at the HVA address
 * 0xffff0000, and the other for * storing the trap handler at 0xffff1000.
 */
void init_kvm_vector(struct kvm_vcpu *vcpu)
{

	struct page *vector_pt_page;
	struct page *first_page;
	hpa_t p, p_old;
	u32 *pt_hva_k;
	u32 pt_hpa_k;
	u32 value_k;
	u32 addr;	
	u32 index;

	printk("init kvm vector !!\n");
	vector_pt_page = alloc_page(GFP_KERNEL);
	if (vector_pt_page == NULL)
		KVM_MMU_BUG();
	pt_hpa_k = page_to_pfn(vector_pt_page) << PAGE_SHIFT;
	pt_hva_k = __va(pt_hpa_k);

	memset(pt_hva_k, 0, PAGE_SIZE);

	/*
	 * save vector table HVA and PGD entry
	 */
	vcpu->arch.vector_pt = pt_hva_k;
	vcpu->arch.vector_pgd_entry =  ( pt_hpa_k
		| PMD_DOMAIN(DOMAIN_GUEST_VECTOR) | PMD_TYPE_TABLE );

	//copy host first page
	first_page = alloc_page(GFP_KERNEL);
	if (first_page == NULL)
		KVM_MMU_BUG();
	p = page_to_pfn(first_page) << PAGE_SHIFT;

	addr = 0xffff0000;
	p_old = hva_to_hpa(current->mm->pgd, addr);
	memcpy(__va(p), __va(p_old), 32);

	flush_icache_range((unsigned long)__va(p), (unsigned long)(__va(p) + PAGE_SIZE));

	index = PT_INDEX(addr); //index = 0xf0

	value_k = (p) | (PTE_TYPE_SMALL & ~PTE_EXT_APX)
		| (PTE_EXT_AP1 & ~PTE_EXT_AP0) | PTE_CACHEABLE;
	pt_hva_k[index] = value_k;

	addr=0xffff1000;
	p = hva_to_hpa(current->mm->pgd, addr);
	index = PT_INDEX(addr); //index = 0xf1
	value_k = (p) | (PTE_TYPE_SMALL & ~PTE_EXT_APX)
		| (PTE_EXT_AP1 & ~PTE_EXT_AP0) | PTE_CACHEABLE;

	pt_hva_k[index] = value_k;

	clean_dcache_area(pt_hva_k, PTRS_PER_PTE * sizeof(pte_t));

	vcpu->arch.vector_gfn = -1;
	vcpu->arch.vector_protection = 0;
}
