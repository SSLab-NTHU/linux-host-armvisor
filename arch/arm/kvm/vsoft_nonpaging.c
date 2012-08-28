/**
 *  @vsoft_nonpaging.c
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

#include <linux/kvm_host.h>
#include <linux/kvm_types.h>
#include <asm/kvm_host.h>
#include <asm/pgtable-hwdef.h>
#include <asm/tlbflush.h>

#include "emulate_arm.h"
#include "vsoft_mmu_hpte.h"

/*
 * guest_mmio_check - to judge if a address is belong to the MMIO region
 * @gpa: the address which is checked
 * 
 * FIXME: 28 is just a self-defined number, but not a general method.
 */
static int guest_mmio_check(gpa_t gpa)
{
	if(gpa >> 28)
		return 1;
	return 0;
}

/*
 * nonpaging_fill_spde
 * @spde
 * @pt
 * 
 */
static inline void nonpaging_fill_spde(u32 *spde, u32 *pt)
{
	u32 value = __pa(pt) | PMD_DOMAIN(DOMAIN_GUEST_KERNEL) | PMD_TYPE_TABLE ;
	fill_spde(spde, value);
	return;
}

/*
 * nonpaging_fill_spte
 * @vcpu
 * @spte
 * @gpa
 * 
 */
static inline void nonpaging_fill_spte(struct kvm_vcpu *vcpu, u32 *spte, gpa_t gpa)
{
	u32 entry;
	gfn_t gfn = (gpa & PAGE_MASK) >> PAGE_SHIFT;
	hpa_t hpa = gfn_to_pfn(vcpu->kvm, gfn) << PAGE_SHIFT;

	entry = hpa | PTE_EXT_AP1 | (PTE_EXT_AP0 & (~PTE_EXT_APX) & (~PTE_EXT_XN));
	entry = entry | PTE_TYPE_SMALL | PTE_CACHEABLE | PTE_BUFFERABLE;
	fill_spte(spte, entry);
	return;
}

/*
 * nonpaging_map
 * @vcpu
 * @gva: the requested guest virtual address
 *
 * Only need to check the host page table for constructing the SPT.
 */
static int nonpaging_map(struct kvm_vcpu *vcpu, gva_t gva)
{
	u32 *root;
	u32 *pt;
	int index;
	
	u32 *spde;
	u32 *spte;

	struct kvm_mmu_spage *spage;

	root = __va(vcpu->arch.mmu.root_hpa);
	index = ROOT_INDEX(gva);
	spde = &root[index];
	if(*spde == NULL_ENTRY) {
		spage = mmu_alloc_pseudo_pt_spage(vcpu, index, spde, 0);
		if(!spage) 
			return MMU_FAILED;
		pt = spage->pt;
		nonpaging_fill_spde(spde, pt);
	} else {
		pt = GET_PT_HVA(*spde);
	}
	
	index = PT_INDEX(gva);
	spte = &pt[index];
	if(*spte == NULL_ENTRY) {
		nonpaging_fill_spte(vcpu, spte, gva);
	}

	return MMU_OK;
}

/*
 * handle_nonpaging_fault
 * @vcpu
 * @gva: the requested guest virtual address
 * @fault_type: It is useless but just for fitting the function format
 *
 * There is no guest page table here, so just check whether gpa is belong
 * to the MMIo region.
 */
static int handle_nonpaging_fault(struct kvm_vcpu *vcpu, gva_t gva, u32 fault_type)
{
	gpa_t gpa = gva;
	int r;

	if (guest_mmio_check(gpa)) {
		r = MMU_MMIO;
		goto out;
	}
	r = nonpaging_map(vcpu, gva);

out:
	return r;
}

/*
 * non_paging_free
 * @vcpu
 */
static void nonpaging_free(struct kvm_vcpu *vcpu)
{
	mmu_zap_all_spages(vcpu->kvm);
	return;
}

/*
 * nonpaging_alloc_root
 * @vcpu
 * 
 * Get a free memory page and store the address in vcpu->arch.mmu.root_hpa 
 */
static void nonpaging_alloc_root(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_spage *spage;
	spage = mmu_alloc_root_spage(vcpu, PSEUDO_ROOT_GFN, PSEUDO_ROOT);
	if(!spage) KVM_MMU_BUG(); 

	vcpu->arch.mmu.root_hpa = __pa(spage->root);
	return;
}

/*
 * nonpaging_gva_to_gpa
 * @vcpu: It is useless but just for fitting the function format
 * @vaddr
 */
static gpa_t nonpaging_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t vaddr)
{
	return (gpa_t)vaddr;
}

/*
 * vsoft_nonpaging_context
 * @vcpu
 * 
 * Set the abort-handling function when using a software supported
 * virtualization in ARM V6 memory architecture with MMU disabled.
 */
void vsoft_nonpaging_context(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;

	context->handle_fault = handle_nonpaging_fault;
	context->alloc_root = nonpaging_alloc_root;
	context->gva_to_gpa = nonpaging_gva_to_gpa;
	context->root_hpa = INVALID_PAGE;
	context->free = nonpaging_free;

	clear_fast_trap_table();
	printk("======vsoft_nonpaging_context=========\n");
	return;
}
