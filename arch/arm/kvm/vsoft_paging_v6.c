/**
 *  @vsoft_paging_v6.c
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
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_host.h>
#include <asm/pgtable-hwdef.h>
#include <asm/tlbflush.h>
#include <asm/ptrace.h>
#include <asm/memory.h>

#include "emulate_arm.h"
#include "vsoft_vcpu.h"
#include "mmu.h"
#include "vsoft_mmu_hpte.h"

#define UNMAPPED_GVA (~(gpa_t)0) //0xffffffff
#define NO_MISS		0
#define ROOT_MISS	1
#define PT_MISS		2

/*
 * get_ttbr_value
 * @vcpu
 */
static u32 get_ttbr_value(struct kvm_vcpu *vcpu)
{
	u32 r = 0;
	if(!(vcpu->arch.cp15.c2_control & 0x7))
		r = vcpu->arch.cp15.c2_base0 & vcpu->arch.cp15.c2_base_mask;
	else
		BUG();
	return r;
}

/*
 * guest_mmu_walker - walking through the guest page table.
 * @walker: store the result after walking the guest PTB
 * @vcpu:
 * @addr: the guest virtual address that caused a trap
 *
 * Note that it is a two-level page table in ARM v6 architecture.
 * If the last 2 bits of the GOS descriptor is 00, then it is a true
 * translation fault (section or page table type).
 */
static int guest_mmu_walker(struct guest_walker *walker,
		struct kvm_vcpu *vcpu, gva_t addr)
{
	u32 root;	//Guest TTBR Value
	u32 index;	//index owns offset
	u32 pde_desc;
	u32 pte_desc;
	u32 pde_gpa;
	u32 pte_gpa;
	u32 type;
	u32 gpa = 0;

	root = get_ttbr_value(vcpu);	

	index = ROOT_INDEX(addr);
	pde_gpa = root | (index << 2);

	kvm_read_guest(vcpu->kvm, pde_gpa, &pde_desc, sizeof(pde_desc));

	if((pde_desc & PMD_TYPE_MASK) == 0) {
		vcpu->arch.guest_c5_data &= ~0xf;
		vcpu->arch.guest_c5_data |= 0x5;
		goto mmu_inject_fault;
	} 
	walker->pde_desc = pde_desc;

	type = pde_desc & PMD_TYPE_MASK;
	walker->map_type = type;

	if (type == PMD_TYPE_TABLE) {
		walker->pt_table_gpa = pde_desc & COARSE_PT_BASE_MASK;
		index = PT_INDEX(addr);
		pte_gpa = walker->pt_table_gpa | (index << 2);

		kvm_read_guest(vcpu->kvm, pte_gpa, &pte_desc,
			 sizeof(pte_desc));
		walker->pte_desc = pte_desc;

		if ((pte_desc & PTE_TYPE_MASK) == 0) {
			vcpu->arch.guest_c5_data &= ~0xf;
			vcpu->arch.guest_c5_data |= 0x7;
			goto mmu_inject_fault;
		}
	}

	if (type == PMD_TYPE_SECT)
		gpa = (walker->pde_desc & SECTION_MASK)
			| (addr & ~SECTION_MASK) ;
	//else
	else if (type == PMD_TYPE_TABLE)
		gpa = (walker->pte_desc & PAGE_MASK)
			| (addr & ~PAGE_MASK );

	walker->gpa = gpa;

	walker->domain_index = (walker->pde_desc & (0xf << 5)) >> 5;
	walker->domain_val = (vcpu->arch.cp15.c3
		 & domain_val(walker->domain_index, DOMAIN_MANAGER)) >> 2 * (walker->domain_index);
	return 0;

mmu_inject_fault:
	return MMU_INJECT_FAULT;
}

/*
 * paging_convert_to_int - extract particular bits of a descriptor
 * @n: start at which bit
 * @m: end at which bit
 * @inst: the input instruction
 *
 * This function would return the bits between the n-th ans m-th but of
 * an instruction in binary.
 */
static unsigned int paging_convert_to_int(size_t n,size_t m,u32 inst)
{
	int base = 1;
	int res = 0;
	size_t i;
	for (i = n; i <= m; i++) {
		if (test_bit(i, &inst))
			res += base;
		base <<= 1;
	}
	return res;
}

/*
 * decode_opcode2 - decode opcode2 field of the descriptor 
 * @vcpu:
 * @domain_val: the domain field of the descriptor
 * @inject_fault: flag the record whether it is a true translation fault
 * @opcode 2: the opcode2 field of the descriptor
 *
 * In the progress handing abort, there is a possibility that the abort
 * trap is caused because of some kinds of load/store instruction.  
 * Here we can figure out which L/S instruction really is by decoding the
 * opcode2 field, such as STRT, LDRT, STRBT, and LDRBt.
 */
#define OPCODE2_STRT	0x2
#define OPCODE2_LDRT	0x3
#define OPCODE2_STRBT	0x6
#define OPCODE2_LDRBT	0x7
static int decode_opcode2(struct kvm_vcpu *vcpu, int domain_val, 
				int *inject_fault, u32 inst, u32 opcode2)
{
	int r = 0;
	if(test_bit(26, &inst)) {
		switch(opcode2) {
		case OPCODE2_STRT:
		case OPCODE2_LDRT:
		case OPCODE2_STRBT:
		case OPCODE2_LDRBT:
			if (domain_val == DOMAIN_MANAGER) {
				vcpu->arch.is_mmio_inst = 0;
				kvmarm_emulate_instruction(vcpu, CRITICAL_INST);
				r = MMU_OK;
			} else {
				*inject_fault = 1;
			}
			break;
		default:
			break;
		}//switch
	}//test bit 26
	return r;
}

/*
 * guest_decode_permission
 * @vcpu:
 * @domain_val: the domain field of the descriptor
 * @inject_fault: flag the record whether it is a true translation fault
 *
 * This function would check whether it is a permission fault (user mode)
 * or it is a sensitive instruction (SVC mode) by checking the excution
 * mode.  Then we can know if it is a load/store instruction by inspecting
 * the opcode field.
 */
static int guest_decode_permission(struct kvm_vcpu *vcpu, int domain_val,
		int *inject_fault)
{
	int r = 0;
	if ((vcpu->arch.virtual_cpsr & MODE_MASK) == USR_MODE) {
		*inject_fault = 1;
	} else if ((vcpu->arch.virtual_cpsr & MODE_MASK) == SVC_MODE) {
		u32 inst =  vcpu->arch.trapped_inst;
		u32 opcode2 = paging_convert_to_int(24, 24, inst);
		u32 temp = paging_convert_to_int(20, 22, inst);
		u32 op_code = paging_convert_to_int(20, 27, inst);

		if (op_code >= 0x40 &&  op_code <= 0x7f) {
			opcode2 = opcode2 << 3;
			opcode2 = opcode2 + temp;
			r = decode_opcode2(vcpu, domain_val, 
				inject_fault, inst, opcode2);
		}
	}
	return r;
}

/*
 * guest_check_fault - check the permission
 * @vcpu:
 * @exit_reason: the reason that make guest exits its native execution
 * @domain_val: the domain field of the descriptor
 * @map_type: a page table or a section
 * @write_fault: the bit 11 in data fault status register format
 * 	(0: read, 1: write), and it can be updated only in this function.
 *
 * After walking guest page table for GPA, we need to inspect whether the
 * access is permitted or not.  Here we assume that there is no domain
 * faults.
 */
#define C5_RW_BIT	(1 << 11)
#define C5_FAULT_STATUS 0xf
#define PERM_FAULT_SECT	0xd
#define PERM_FAULT_PAGE 0xf
static int guest_check_fault(struct kvm_vcpu *vcpu, u32 exit_reason,
		u32 domain_val,int map_type, int *write_fault)
{
	int inject_fault = 0;
	int r = 0;
	if (exit_reason == ARM_INTERRUPT_DATA_ABORT) {
		// check write fault
		if ((vcpu->arch.guest_c5_data & C5_FAULT_STATUS) == PERM_FAULT_PAGE) {
			*write_fault = vcpu->arch.guest_c5_data & C5_RW_BIT;
			r = guest_decode_permission(vcpu, domain_val,
				&inject_fault);
		}
	}

	if (inject_fault == 1) {
		if (map_type == PMD_TYPE_SECT) {
			vcpu->arch.guest_c5_data &= ~C5_FAULT_STATUS;
			vcpu->arch.guest_c5_data |= PERM_FAULT_SECT;
		} else if (map_type == PMD_TYPE_TABLE) {
			vcpu->arch.guest_c5_data &= ~C5_FAULT_STATUS;
			vcpu->arch.guest_c5_data |= PERM_FAULT_PAGE;
		}
		r = MMU_INJECT_FAULT;
	}
	return r;
}

/*
 * gpa_to_hpa - convert GPA to host physical address
 * @vcpu:
 * @gpa: guest physical address
 */
static hpa_t gpa_to_hpa(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	struct page *page;
	page = gfn_to_page(vcpu->kvm, gpa >> PAGE_SHIFT);
	if (!page)
		KVM_MMU_BUG();

	return ((hpa_t)page_to_pfn(page) << PAGE_SHIFT)
		| (gpa & (PAGE_SIZE-1));
}

/*
 * reset_vector_table
 * @vcpu
 * 
 * This function would reset the vector table (@0xffff00000)and the second
 * page (@0xffff1000) which stores the shadow register files.  If the
 * memory optimization feature is turned on, then does nothing because all
 * the mapping information is deliverd to the VMM "positively"
 */
#ifndef CONFIG_MEM_OPT
void reset_vector_table(struct kvm_vcpu *vcpu) {
	u32 index_1 = 0xf0;
	u32 first_entry_k;
	u32 index_2 = 0xf1;
	u32* table_va_k;
	u32 second_entry_k;  

	printk("--> reset_vector_table\n");
	table_va_k = vcpu->arch.vector_pt;

	first_entry_k = table_va_k[index_1];
	second_entry_k = table_va_k[index_2];

	memset(table_va_k, 0, PAGE_SIZE);

	table_va_k[index_1] = first_entry_k;
	table_va_k[index_2] = second_entry_k;

	clean_dcache_area(table_va_k, PTRS_PER_PTE * sizeof(pte_t));

	vcpu->arch.vector_gfn = -1;
	vcpu->arch.vector_protection = 0;
	return;
}
#else
void reset_vector_table(struct kvm_vcpu *vcpu) {}	
#endif

/*
 * set_spte - set the configuration in the shadow page table
 * @vcpu
 * @walker: store the information in guest page table
 * @spte_hva: 
 */
static u32 set_spte(struct kvm_vcpu *vcpu, struct guest_walker *walker,
		u32 *spte_hva ) {
	hpa_t base_hpa = gpa_to_hpa(vcpu, walker->gpa & PAGE_MASK);
	u32 spte_desc = base_hpa;
	u32 type = walker->pde_desc & PMD_TYPE_MASK;

	if (type == PMD_TYPE_SECT) {
		if (walker->pde_desc & PMD_SECT_XN)
			spte_desc |= PTE_EXT_XN;
		if (walker->pde_desc & PMD_SECT_BUFFERABLE)
			spte_desc |= PTE_BUFFERABLE;
		if (walker->pde_desc & PMD_SECT_TEX(1))
			spte_desc |= PTE_EXT_TEX(1);
		if (walker->pde_desc & PMD_SECT_TEX(2))
			spte_desc |= PTE_EXT_TEX(2);
		if (walker->pde_desc & PMD_SECT_TEX(4))
			spte_desc |= PTE_EXT_TEX(4);
		if (walker->pde_desc & PMD_SECT_S)
			spte_desc |= PTE_EXT_SHARED;

		/*
		 * FIXME:rw : na --> to reduce overprotection problem
		 */
		spte_desc &= ~PTE_EXT_APX;
		spte_desc &= ~PTE_EXT_AP1;
		spte_desc |= PTE_EXT_AP0;

		spte_desc &= ~PTE_EXT_NG;
		/*
		 * FIXME: XN
		 */
		spte_desc &= ~PTE_EXT_XN;
		spte_desc |= PTE_CACHEABLE;
		spte_desc |= PTE_TYPE_SMALL;
	} else if (type == PMD_TYPE_TABLE) {
		spte_desc |= walker->pte_desc & ((1 << PAGE_SHIFT) - 1); 
		spte_desc |= PTE_CACHEABLE;
	}
	fill_spte(spte_hva, spte_desc);
	return 0;
}

/*
 * paging_map_v6_guest
 * @vcpu
 * @gva: the requested virtual address of the guest OS
 * @walker: store the information in guest page table
 * @spde_hva: the L1 shadow page table entry
 * @spte_hva: the L2 shadow page table entry
 *
 * This function would search the SPT for the mapping, if it does not exist,
 * then create a new SPT entry.
 */
static u32 paging_map_v6_guest(struct kvm_vcpu *vcpu, gva_t gva,
	struct guest_walker *walker, u32 **spde_hva, u32 **spte_hva) {
	u32 *root;
	u32 *pt;
	u32 index;
	u32 desc;

	u32 *spde;
	u32 *spte;
	u32 type;

	struct kvm_mmu_spage *spage = NULL;
	int r = NO_MISS;

	root = __va(vcpu->arch.mmu.root_hpa);
	index =  ROOT_INDEX(gva);
	spde = &root[index];

	type = walker->map_type;

	if (*spde == NULL_ENTRY) {
		if (type == PMD_TYPE_SECT) {
			spage = mmu_alloc_pseudo_pt_spage(vcpu, index, spde, gva);
		} else if (type == PMD_TYPE_TABLE) {
			gfn_t pt_hash_idx = ((walker->pt_table_gpa) >> PT_PAGE_SHIFT);
			spage = mmu_alloc_pt_spage(vcpu, pt_hash_idx, PT,
			spde, gva);
		}

		if (spage == NULL)
			BUG();

		//setup spde
		desc = __pa(spage->pt);

		desc |= (walker->pde_desc & PTE_EXT_APX);
		desc |= PMD_DOMAIN(walker->domain_index + 3);
		desc &= ~(PMD_TYPE_MASK);
		desc |= PMD_TYPE_TABLE;

		fill_spde(spde, desc);
		r |= ROOT_MISS;
	}

	//2. process second level
	pt =  __va((*spde) & COARSE_PT_BASE_MASK); 
	index = PT_INDEX(gva);
	spte = &pt[index];

	*spde_hva = spde;
	*spte_hva = spte;

	if (*spte == NULL_ENTRY) {
		r |= PT_MISS;
		set_spte(vcpu, walker, spte);
	}

	return r;
}

/*
 * do_protection - set input VA read only in user mode
 * @spte_hva: shadow page table entry
 */
static void do_protection(u32 *spte_hva) 
{
	u32 value = (*spte_hva) & (~PTE_EXT_APX);
	value |= PTE_EXT_AP1;
	value &= ~PTE_EXT_AP0;
	fill_spte(spte_hva, value);
}

/*
 * up_permission - set input VA full access
 * @spte_hva
 */
static void up_permission(u32 *spte_hva)
{
	u32 value = (*spte_hva) & (~PTE_EXT_APX);
	value |= (PTE_EXT_AP1 | PTE_EXT_AP0);
	fill_spte(spte_hva, value);
}

/*
 * paging_map
 * @vcpu
 * @addr: requested virtual address
 * @walker: store the information in guest page table
 *
 * call a function to create SPT entry, then check whether the memory page
 * (or address) has other meanings in Linux kernel.
 * FIXME: 0xbf000000 is replaced by TASK_SIZE
 */
static u32 *paging_map(struct kvm_vcpu *vcpu, gva_t addr,
				struct guest_walker *walker)
{
   
	u32 *spde_hva;
	u32 *spte_hva;
	struct kvm_mmu_spage *spage;
	int mode;
	int r;

	u32 gfn = walker->gpa >> PAGE_SHIFT;

	r = paging_map_v6_guest(vcpu, addr, walker, &spde_hva, &spte_hva);

	if(r == NO_MISS)
		return spte_hva;
	else if(r == ROOT_MISS)
		return NULL;

	mode = get_guest_mode(vcpu);
	
	//Client Domain
	if (mode == KERNEL && addr >= TASK_SIZE) {
		//default : DOMAIN_GUEST_TABLE = client
		*spde_hva &= ~PMD_DOMAIN(0xf);
		*spde_hva |= PMD_DOMAIN(DOMAIN_GUEST_KERNEL);
		/*
		 * FIXME: GFN 4, 5, 6, 7 for protecting ROOT.
		 * However, it is really a bad program writing.
		 */
		if(gfn!=4 && gfn!=5 && gfn!=6 && gfn!=7) {
			spage = mmu_lookup_one_spage(vcpu, gfn);
			if (spage != NULL) {
				do_protection(spte_hva);
				return NULL;
			} 
		}
#ifndef CONFIG_MEM_OPT 
		if (gfn == vcpu->arch.vector_gfn) {
			do_protection(spte_hva);
			return NULL;
		}
#endif			
		if(vcpu->arch.vector_protection == 0 && (addr >= 0xfff00000 && addr <= 0xffffffff)) {
			vcpu->arch.vector_gfn = walker->pt_table_gpa >> PAGE_SHIFT; 
			vcpu->arch.vector_protection = 1;
#ifndef CONFIG_MEM_OPT 
			rmap_write_protect(vcpu, vcpu->arch.vector_gfn);
#endif			
		}
		//up permission!!
		up_permission(spte_hva);	

		if(addr < 0xfff00000)
			rmap_add(vcpu, spte_hva);
	}
	return NULL;
}

/*
 * handle_protection_fault
 * @vcpu
 * @addr: the requested virtual address of the guest OS
 * @walker: store the information in guest page table
 * @spte_hva:
 *
 * After walking through the guest page table, we need to judge whether it is
 * a true permission fault by checking the permission setting in the guest OS.
 */
static u32 handle_protection_fault(struct kvm_vcpu *vcpu, gva_t addr,
				struct guest_walker *walker, u32 *spte_hva)
{
	struct kvm_mmu_spage *spage;
	int index;
	int pt_fault;

	int mode = get_guest_mode(vcpu);
	u32 gfn = walker->gpa >> PAGE_SHIFT;

#ifndef CONFIG_MEM_OPT
//protect_pt:	
	pt_fault = handle_pt_fault(vcpu, gfn);	
	if(pt_fault) {
		goto reset_spte;
	}

//protect_vector:
	if(vcpu->arch.vector_gfn == gfn) {
		reset_vector_table(vcpu);
		goto reset_spte; 
	}
#endif

//protect_root:
	spage = mmu_lookup_root_spage(vcpu,gfn);
	if(!spage)
		goto reset_spte;
	index = walker->gpa & ~(PAGE_MASK << 2);
	index = index >> 2;
	if(spage->root == __va(vcpu->arch.mmu.root_hpa)) {
		fill_spde(&spage->root[index], 0);
		return MMU_SPT;
	} 
	else {
		mmu_zap_spage(spage);
		goto reset_spte; 
	}

reset_spte:
	set_spte(vcpu, walker, spte_hva);
	if (mode == KERNEL && addr >= TASK_SIZE) {
		up_permission(spte_hva);
		if(addr < 0xfff00000)
			rmap_add(vcpu,spte_hva);
	}
	return MMU_OK;
}

/*
 * paging_gva_to_gpa
 * @vcpu
 * @vaddr: input guest virtual address
 *
 * Return the guest physical address corresponding to the input GVA.
 */
static gpa_t paging_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t vaddr)
{
	struct guest_walker walker;
	gpa_t gpa = UNMAPPED_GVA;
	int r;

	r = guest_mmu_walker(&walker, vcpu, vaddr );

	if (r == 0)
		gpa = walker.gpa;

	return gpa;
}

/*
 * is_mmio - to judge if a address is belong to the MMIO region
 * @gpa: the address which is checked
 *
 * FIXME: 28 is just a self-defined number, but not a general method.
 */
static int is_mmio(gva_t gpa)
{
	if (gpa >> 28 && gpa != UNMAPPED_GVA) 
		return 1;
	else 
		return 0;
}

/*
 * paging_handle_fault - the start of a abort-handling process
 * @vcpu
 * @gva: the resuested virtual address of the guest OS
 * @fault_type: this parameter is called by refernce and its value would 
 * be set when guest_check_fault.
 *
 * The abort handling process: 1.walk through the guest page table  2.check
 * the true permission fault  3.checking the SPT  4.judge if MMIO address
 * 5.update the SPT  6.hidden permission fault
 */
static int paging_handle_fault(struct kvm_vcpu *vcpu, gva_t gva, u32 fault_type)
{
	int write_fault = 0;
	int r;
	struct guest_walker walker;
	struct kvm_mmu_spage *spage;
	u32 *spte_hva;

	memset(&walker, -1, sizeof(walker));

	r = guest_mmu_walker(&walker, vcpu, gva); 
	
	if (r == MMU_INJECT_FAULT) {
		return MMU_INJECT_FAULT;
	}
   
	r = guest_check_fault(vcpu, fault_type, walker.domain_val,
		walker.map_type, &write_fault);
	if (r == MMU_INJECT_FAULT || r == MMU_OK) 
		return r;

	if (is_mmio(walker.gpa)) {
		vcpu->arch.mmu.mmio_addr = walker.gpa;
		kvm_profiling_count(&vcpu->stat.mmio_trap);
		return MMU_MMIO;
	}

	spage = vcpu->arch.mmu.root;
	vcpu->arch.mmu.root_hpa = __pa(spage->root);

	spte_hva  = paging_map(vcpu,gva,&walker);
#ifdef CONFIG_PROFILE_COUNT
	if(spte_hva == NULL) {
		if(fault_type == ARM_INTERRUPT_PREF_ABORT)
			kvm_profiling_count(&vcpu->stat.inst_translation_miss);
		else if (fault_type == ARM_INTERRUPT_DATA_ABORT)
			kvm_profiling_count(&vcpu->stat.data_translation_miss);
	}
#endif
	r = MMU_OK;
	if(write_fault && spte_hva) {
		kvm_profiling_count(&vcpu->stat.protection_fault);
		r = handle_protection_fault(vcpu,gva,&walker, spte_hva);
	}
	return r;
}

/*
 * kvm_fill_pt_pv - fill a SPT entry in para-virtualization way
 * @vcpu
 * 
 * only fill the entry for user mode shadow PT
 */
int kvm_fill_pt_pv(struct kvm_vcpu *vcpu) 
{
	struct kvm_mmu_spage *spage;
	struct kvm_mmu_spage *root;
	int r;
	u32* spte_hva;
	u32 spte = 0;
	u32 pt_gpa;
	u32 pt_gfn;
	u32 pt_hash_idx;
	u32 map_gfn;

	//parse guest instruction
	u32 gpt_Rd_index = TRANSFER_BITSEG(12, 15, vcpu->arch.trapped_inst);
	u32 gpt_Rn_index = TRANSFER_BITSEG(16, 19, vcpu->arch.trapped_inst);
	u32 new_gpte = vcpu->arch.regs[gpt_Rd_index];
	u32 pt_index = ((vcpu->arch.regs[gpt_Rn_index] & 0x3ff));

	gva_t gva =  vcpu->arch.regs[gpt_Rn_index];


	//check mmio
	u32 map_gpa = new_gpte & PAGE_MASK;
	if(is_mmio(map_gpa)) 
		goto out;

	//create spte
	if(new_gpte) {
		u32 map_hpa = gpa_to_hpa(vcpu, map_gpa);
		spte = (map_hpa | (new_gpte & (~PAGE_MASK)));
	}

	pt_gpa = vcpu->arch.mmu.gva_to_gpa(vcpu, gva);
	pt_gfn = pt_gpa >> PAGE_SHIFT;
	//check vector 	
	if (pt_gfn == vcpu->arch.vector_gfn) {
		//kernel vector
		spte_hva = (u32*)((u32)vcpu->arch.vector_pt | pt_index);
		*spte_hva= spte;
		//up permission
		up_permission(spte_hva);
		//(assume : no guest page table will be mapped)
		goto out;
	}
	pt_hash_idx = pt_gpa >> PT_PAGE_SHIFT;

	r = mmu_topup_memory_caches(vcpu);
	if(r) KVM_MMU_BUG();

	/*
	 * FIXME: how about pte_chain and R-map?
	 */
	spage = mmu_lookup_spage(vcpu, pt_hash_idx, PT);
	if(!spage) 
	goto out;

	spte_hva = (u32*)((u32)spage->pt | pt_index);
	map_gfn = map_gpa >> PAGE_SHIFT;
	root = mmu_lookup_one_spage(vcpu, map_gfn);
	if(root) {
		do_protection(spte_hva);
	}
	else {
		if(spage->pt_map >= 0xbf000000) {
			up_permission(spte_hva);
			rmap_add(vcpu, spte_hva);
		}
		fill_spte(spte_hva, spte);
	}
out:
	return 0;
}

/*
 * kvm_free_pt_pv - free the memory space
 * @vcpu
 * 
 * This function would be executed only when the memory optimization is
 * turned on (para-virtulaiztion).  0xffff1990 is just a self-designed
 * address.  The patched GOS would put the guest PFN (of the page table page
 * which is requested to free) at 0xffff1990.
 */
void kvm_free_pt_pv (struct kvm_vcpu *vcpu)
{
	long* ptr = (long*)0xffff1990;
	u32 gfn = *ptr;

	handle_pt_fault(vcpu, gfn);
}

/*
 * get_guest_ttbr0 - return the GFN of the value in guest TTBR0
 * @vcpu
 */
static gfn_t get_guest_ttbr0(struct kvm_vcpu *vcpu)
{
	if(!(vcpu->arch.cp15.c2_control & 7)) 
		return (vcpu->arch.cp15.c2_base0 >> (PAGE_SHIFT));
	else 
		KVM_MMU_BUG();
}

/*
 * paging_alloc_root
 * @vcpu
 * 
 * Allocate a shadow page (stored in vcpu->arch.mmu.root)
 * and get the physical frame (stored in vcpu->arch.mmu.root_hpa).
 */
static void paging_alloc_root(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_spage *spage;

	gfn_t root_gfn = get_guest_ttbr0(vcpu);

	spage = mmu_alloc_root_spage(vcpu, root_gfn, ROOT);
	if(!spage) KVM_MMU_BUG(); 

	vcpu->arch.mmu.root = spage;
	vcpu->arch.mmu.root_hpa = __pa(spage->root);
	return;
}

/*
 * paging_free
 * @vcpu
 */
static void paging_free(struct kvm_vcpu *vcpu)
{
	mmu_zap_all_spages(vcpu->kvm);
	return;
}

/*
 * vsoft_paging_context
 * @vcpu
 * 
 * Set the abort-handling function when using a software supported
 * virtualization in ARM V6 memory architecture with MMu enabled.
 */
void vsoft_paging_context(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;
	context->handle_fault = paging_handle_fault;
	context->alloc_root = paging_alloc_root;
	context->gva_to_gpa = paging_gva_to_gpa;
	context->free = paging_free;
	context->root_hpa = INVALID_PAGE;

	clear_fast_trap_table();
	printk("======vosft_paging_context=========\n");
	return;
}

