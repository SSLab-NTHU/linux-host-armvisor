/**
 *  @mmu.h
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

#ifndef __ARM_KVM_MMU_H__
#define __ARM_KVM_MMU_H__

#define VALID_PAGE(x) ((x) != INVALID_PAGE)
#define ARM_CP15_C1_MMU	0x00000001 /* Paging */

struct guest_walker {
	int map_type;
	u32 gpa;
	u32 pt_table_gpa;
	u32 pde_desc;
	u32 pte_desc;
	u32 domain_index;
	u32 domain_val;
};

int mmu_topup_memory_caches(struct kvm_vcpu *vcpu);
void *mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc, size_t size);
void mmu_destroy_caches(void);
int mmu_pool_init(void);
 
void c15_reset_mmu(struct kvm_vcpu *vcpu);
void c15_reset_ttbr0(struct kvm_vcpu *vcpu);
void c15_reset_domain(struct kvm_vcpu *vcpu, u32 guest_domain);

static inline int is_vext(struct kvm_vcpu *vcpu)
{
	return 0;
}

static inline int is_paging(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.cp15.c1_sys & ARM_CP15_C1_MMU;
}

int kvm_mmu_page_fault(struct kvm_vcpu *vcpu, gva_t addr, u32 exit_reason);
int kvm_mmu_load(struct kvm_vcpu *vcpu);
int kvm_mmu_reload(struct kvm_vcpu *vcpu);
void kvm_mmu_reset_context(struct kvm_vcpu *);
void kvm_mmu_setup(struct kvm_vcpu *vcpu);
unsigned int kvm_mmu_calculate_mmu_pages(struct kvm *kvm);
void kvm_mmu_change_mmu_pages(struct kvm *kvm, unsigned int kvm_nr_mmu_pages);
void kvm_mmu_module_exit(void);
int kvm_mmu_module_init(void);

#endif /* __ARM_KVM_MMU_H__ */
