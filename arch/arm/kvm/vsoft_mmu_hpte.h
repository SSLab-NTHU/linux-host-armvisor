/**
 *  @vsoft_mmu_hpte.h
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

#ifndef __ARM_VSOFT_MMU_SPAGE_H
#define __ARM_VSOFT_MMU_SPAGE_H

#include <linux/list.h>
#include <linux/kvm_types.h>
#include <asm/pgtable-hwdef.h>
#include <asm/page.h>

#define KERNEL		0
#define USER		1

#define ROOT		0
#define PSEUDO_ROOT 	1
#define PT 		2
#define PSEUDO_PT	3

#define PSEUDO_ROOT_GFN	0

#define NULL_ENTRY	0

#define ROOT_LEVEL_BITS	12
#define PT_LEVEL_BITS	8
#define PT_PAGE_SHIFT 	10

#define DOMAIN_GUEST_KERNEL 6 
#define DOMAIN_GUEST_VECTOR 7

#define PT_TABLE_ENTRY	(1 << PT_LEVEL_BITS)

#define COARSE_PT_BASE_MASK (~((1UL << 10) - 1))
#define SECTION_BASE_MASK (~((1UL << 20) - 1))

#define GET_PT_HVA(spde) __va((spde & COARSE_PT_BASE_MASK))

#define GET_PT_ID(pt_gpa) \
	((pt_gpa & (~PAGE_MASK)) >> 10)

#define PT_SIZE		(1UL << (PT_LEVEL_BITS +2))

#define PT_MAP_MASK	(~((1UL << 20) - 1))

#define ROOT_INDEX(addr) \
	((addr) >> (PT_LEVEL_BITS + PAGE_SHIFT))
#define PT_INDEX(addr) \
	((addr >> PAGE_SHIFT) & ((1UL << PT_LEVEL_BITS) -1))

#define INVALID_PAGE (~(hpa_t)0)

#define KVM_MMU_BUG() BUG()

#define RMAP_EXT 2

struct kvm_rmap_desc {
	u32 *shadow_ptes[RMAP_EXT];
	struct kvm_rmap_desc *more;
};

struct kvm_mmu_spage {
	struct list_head mmu_link;
	struct hlist_node hash_link;

	gfn_t gfn;
	u8 spt_type;
	u32 pt_map;

	union {
		u32 *root;
		u32 *pt;
	};

	//u8 multimapped;
	//union {
		u32 *parent_pte;
		//struct hlist_head parent_ptes;
	//};
};

void rmap_add(struct kvm_vcpu *vcpu, u32 *spte);
void rmap_remove(u32 *spte);
void rmap_write_protect(struct kvm_vcpu *vcpu, u32 gfn);

void fill_spde(u32 *entry, u32 value);
void fill_spte(u32 *entry, u32 value);

//should put in Guest interface
int get_guest_mode(struct kvm_vcpu *vcpu);

struct kvm_mmu_spage* mmu_lookup_spage(struct kvm_vcpu *vcpu, gfn_t gfn, u8 spt_type);
struct kvm_mmu_spage* mmu_lookup_root_spage(struct kvm_vcpu *vcpu, gfn_t gfn);
struct kvm_mmu_spage* mmu_lookup_one_spage(struct kvm_vcpu *vcpu, gfn_t gfn);

struct kvm_mmu_spage* mmu_alloc_spage(struct kvm_vcpu *vcpu, gfn_t gfn, 
	u8 spt_type, u32 *parent_pte, gva_t map_gva);

#define mmu_alloc_root_spage(vcpu, gfn, spt_type) \
	mmu_alloc_spage(vcpu, gfn, spt_type, NULL, 0)

#define mmu_alloc_pseudo_pt_spage(vcpu, gfn, spde, map_gva) \
	mmu_alloc_spage(vcpu, gfn, PSEUDO_PT, spde, map_gva)

#define mmu_alloc_pt_spage mmu_alloc_spage

struct kvm_mmu_spage* mmu_alloc_spage_pv(struct kvm_vcpu *vcpu, gfn_t gfn);
void mmu_zap_spage(struct kvm_mmu_spage *spage);
void mmu_zap_all_spages(struct kvm *kvm);
int handle_pt_fault(struct kvm_vcpu *vcpu, gfn_t gfn);
#endif /* __ARM_MMU_SPAGE_H */

