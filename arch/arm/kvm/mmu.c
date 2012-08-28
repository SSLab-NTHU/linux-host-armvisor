/**
 *  @mmu.c
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
#include <linux/mm.h>
#include <linux/kvm_host.h>
#include <asm/tlbflush.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_host.h>
#include "mmu.h"
#include "vsoft_mmu.h"
#include "vsoft_mmu_hpte.h"
#include "vsoft_vcpu.h"
#include "emulate_arm.h"

/* Defined in vsoft_nonpaging.c */
extern void vsoft_nonpaging_context(struct kvm_vcpu *vcpu);
/* Defined in vsoft_paging_v6.c */
extern void vsoft_paging_context(struct kvm_vcpu *vcpu);
/* Defined in vsoft_mmu.c */
extern void vsoft_c15_context(struct kvm_vcpu *vcpu);

static struct kmem_cache *rmap_desc_cachep;
static struct kmem_cache *mmu_spage_header_cachep;
static struct kmem_cache *mmu_pt_cachep; 

/*
 * mmu_topup_memory_cache
 * @cache
 * @base_cache
 * @min
 */
static int mmu_topup_memory_cache(struct kvm_mmu_memory_cache *cache,
		struct kmem_cache *base_cache, int min)
{
	void *obj;

	if (cache->nobjs >= min)
		return 0;
	while (cache->nobjs < ARRAY_SIZE(cache->objects)) {
		obj = kmem_cache_zalloc(base_cache, GFP_KERNEL);
		if (!obj)
			return -ENOMEM;
		cache->objects[cache->nobjs++] = obj;
	}
	return 0;
}

/*
 * mmu_topup_memory_caches
 * @vcpu
 */
int mmu_topup_memory_caches(struct kvm_vcpu *vcpu)
{
	int r;

	r = mmu_topup_memory_cache(&vcpu->arch.mmu_rmap_desc_cache,
			rmap_desc_cachep, 4);
	if (r)
		goto out;
	r = mmu_topup_memory_cache(&vcpu->arch.mmu_spage_header_cache,
			mmu_spage_header_cachep, 4);
	if (r)
		goto out;
	r = mmu_topup_memory_cache(&vcpu->arch.mmu_pt_cache,
			mmu_pt_cachep, 4);
out:
	return r;
}

/*
 * mmu_memory_cache_alloc
 * @mc
 * @size
 * 
 * This is where the memory allocation is implemented and would return an 
 * address of an available memory page.
 */ 
void *mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc, size_t size)
{
	void *p;

	BUG_ON(!mc->nobjs);
	p = mc->objects[--mc->nobjs];
	memset(p, 0, size);
	return p;
}

/*
 * mmu_destroy_caches
 */
void mmu_destroy_caches(void)
{
	if (rmap_desc_cachep)
		kmem_cache_destroy(rmap_desc_cachep);
	if (mmu_spage_header_cachep)
		kmem_cache_destroy(mmu_spage_header_cachep);
	if (mmu_pt_cachep)
		kmem_cache_destroy(mmu_pt_cachep);
}

/*
 * mmu_pool_init - initialize the memory pool
 * 
 * We use the slab machannism in Linux kernel and create three slab cache
 * as the memory pool that we can get available memory space from the cache.
 */
int mmu_pool_init(void)
{
	rmap_desc_cachep = kmem_cache_create("kvm_rmap_desc",
			sizeof(struct kvm_rmap_desc), 0, 0, NULL);
	if (!rmap_desc_cachep)
		goto nomem;

	mmu_spage_header_cachep = kmem_cache_create("kvm_mmu_spage_header",
			sizeof(struct kvm_mmu_spage), 0, 0, NULL);
	if (!mmu_spage_header_cachep)
		goto nomem;

	mmu_pt_cachep = kmem_cache_create("kvm_mmu_pt_cache",
			PT_SIZE, PT_SIZE, 0, NULL);
	if (!mmu_pt_cachep)
		goto nomem;

	return 0;
nomem:
	mmu_destroy_caches();
	return -ENOMEM;

}

/*
 * c15_reset_mmu
 * @vcpu
 */
void c15_reset_mmu(struct kvm_vcpu *vcpu) 
{
	vcpu->arch.mmu.c15_reset_mmu(vcpu);
}

/*
 * c15_reset_ttbr0 
 * @vcpu
 */
void c15_reset_ttbr0(struct kvm_vcpu *vcpu) 
{
	vcpu->arch.mmu.c15_reset_ttbr0(vcpu);
}

/*
 * c15_reset_domain
 * @vcpu
 * @guest_domain
 */
void c15_reset_domain(struct kvm_vcpu *vcpu, u32 guest_domain)
{
	vcpu->arch.mmu.c15_reset_domain(vcpu, guest_domain);
}

/*
 * kvm_mmu_page_fault
 * @vcpu
 * @addr:the requested virtual address 
 * @exit_reason: the reason why guest exits its execution context
 */
int kvm_mmu_page_fault(struct kvm_vcpu *vcpu, gva_t addr, u32 exit_reason)
{
	int r = 0;
	if(is_vext(vcpu))
		;
	else
		r = vsoft_mmu_page_fault(vcpu, addr, exit_reason);

	return r;
}
EXPORT_SYMBOL_GPL(kvm_mmu_page_fault);

/*
 * kvm_mmu_load
 * @vcpu
 */
int kvm_mmu_load(struct kvm_vcpu *vcpu)
{
	int r = mmu_topup_memory_caches(vcpu);
	if (r) KVM_MMU_BUG();

	vcpu->arch.mmu.alloc_root(vcpu);
	return 0;
}

/*
 * kvm_mmu_reload
 * @vcpu
 */
int kvm_mmu_reload(struct kvm_vcpu *vcpu)
{
	if (likely(vcpu->arch.mmu.root_hpa != INVALID_PAGE))
		return 0;
	return kvm_mmu_load(vcpu);
}

/*
 * destroy_mmu_context
 * @vcpu
 */
static void destroy_mmu_context(struct kvm_vcpu *vcpu)
{
	if (VALID_PAGE(vcpu->arch.mmu.root_hpa)) {
		vcpu->arch.mmu.free(vcpu);
		vcpu->arch.mmu.root_hpa = INVALID_PAGE;
	}
}

/*
 * init_mmu_context - set the handling functions in MMU
 * @vcpu
 * 
 * We classify the handling functions accrodind to whether the host CPU
 * support the virtualization extension or not in both cases of MMU is enable
 * or disable.
 */
static void init_mmu_context(struct kvm_vcpu *vcpu)
{
	if (is_vext(vcpu)) {
		1 == 1;
		if (is_paging(vcpu))
			1 == 1;
		else 
			1 == 1;
	} else {
		vsoft_c15_context(vcpu);
		if (is_paging(vcpu))
			vsoft_paging_context(vcpu);
		else 
			vsoft_nonpaging_context(vcpu);
	}
}

/*
 * kvm_mmu_reset_context
 * @vcpu
 */
void kvm_mmu_reset_context(struct kvm_vcpu *vcpu)
{
	destroy_mmu_context(vcpu);
	init_mmu_context(vcpu);
}

/*
 * kvm_mmu_setup - set up the context of MMU
 * @vcpu
 */
void kvm_mmu_setup(struct kvm_vcpu *vcpu)
{
	if(!is_vext(vcpu))
		init_kvm_vector(vcpu);

	init_mmu_context(vcpu);
	c15_reset_domain(vcpu, 0);
}

#define KVM_PERMILLE_MMU_PAGES 20
#define KVM_MIN_ALLOC_MMU_PAGES 64

/*
 * kvm_mmu_calculate_pages
 * @kvm
 * 
 * Caculate MMU pages needed for KVM. 
 * FIXME: Just reference X86 architecture
 */
unsigned int kvm_mmu_calculate_mmu_pages(struct kvm *kvm)
{
	int i;
	unsigned int nr_mmu_pages;
	unsigned int  nr_pages = 0;

	for (i = 0; i < kvm->memslots->nmemslots; i++)
		nr_pages += kvm->memslots->memslots[i].npages;

	nr_mmu_pages = nr_pages * KVM_PERMILLE_MMU_PAGES / 1000;
	nr_mmu_pages = max(nr_mmu_pages,
		(unsigned int) KVM_MIN_ALLOC_MMU_PAGES);

	return nr_mmu_pages;
}

/*
 * kvm_mmu_change_mmu_pages
 * @kvm
 * @kvm_nr_mmu_pages
 */
void kvm_mmu_change_mmu_pages(struct kvm *kvm,
		 unsigned int kvm_nr_mmu_pages)
{
	return;
}

/*
 * kvm_mmu_module_exit
 */
void kvm_mmu_module_exit(void)
{
	/*
	 * TODO: destroy_mmu_context(vcpu);
	 */
	mmu_destroy_caches();
}

/*
 * kvm_mmu_module_init
 */
int kvm_mmu_module_init(void)
{
	int r = mmu_pool_init();
	return r;
}
