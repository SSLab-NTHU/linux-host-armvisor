/**
 *  @vsoft_mmu_hpte.c
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

#include <linux/slab.h>
#include <linux/kvm_host.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/kvm_arm.h>
#include <asm/memory.h>
#include "vsoft_mmu_hpte.h"
#include "mmu.h"

#define KVM_NUM_MMU_SPAGES	32

/*
 * mmu_alloc_rmap_desc
 * @vcpu
 * 
 * Use slab to get a available page from a cache list. 
 */
static struct kvm_rmap_desc *mmu_alloc_rmap_desc(struct kvm_vcpu *vcpu)
{
	return mmu_memory_cache_alloc(&vcpu->arch.mmu_rmap_desc_cache,
				sizeof(struct kvm_rmap_desc)); 
}

/*
 * is_rmap_pte - judge if an PT entry is R-map entry
 * @pte
 */
static int is_rmap_pte(u32 pte)
{
	int permission;

	permission = pte & (PTE_EXT_APX | PTE_EXT_AP1 | PTE_EXT_AP0);
	if (permission == (PTE_EXT_AP1 | PTE_EXT_AP0))
		return 1;
	else 
		return 0;
}

/*
 * rmap_add - add a new entry into R-map
 * @vcpu
 * @spte: shadow page table entry
 */
void rmap_add(struct kvm_vcpu *vcpu, u32 *spte)
{
	struct page *page;
	struct kvm_rmap_desc *desc;
	int i;

	if (!is_rmap_pte(*spte)) 
		return;

	page = pfn_to_page((*spte & PAGE_MASK) >> PAGE_SHIFT);

	if (!page_private(page)) {
		set_page_private(page,(unsigned long)spte);
	} else if (!(page_private(page) & 1)) {
		printk("RMAP ADD Descriptor first : %lu!!\n", (*spte & PAGE_MASK));
		desc = mmu_alloc_rmap_desc(vcpu);
		desc->shadow_ptes[0] = (u32 *)page_private(page);
		desc->shadow_ptes[1] = spte;
		set_page_private(page,(unsigned long)desc | 1);
	} else {
		desc = (struct kvm_rmap_desc *)(page_private(page) & ~1ul);

		while (desc->shadow_ptes[RMAP_EXT-1] && desc->more)
			desc = desc->more;
		if (desc->shadow_ptes[RMAP_EXT-1]) {
			printk("RMAP ADD Descriptor more : %lu!!\n", (*spte & PAGE_MASK));
			desc->more = mmu_alloc_rmap_desc(vcpu);
			desc = desc->more;
		}
		for (i = 0; desc->shadow_ptes[i]; ++i)
			;
		desc->shadow_ptes[i] = spte;
	}
}

/*
 * mmu_free_rmap_desc
 * @rd
 */
static void mmu_free_rmap_desc(struct kvm_rmap_desc *rd)
{
	kfree(rd);
}

/*
 * rmap_desc_remove_entry
 * @page
 * @desc
 * @i
 * @prev_desc
 * 
 * 
 */
static void rmap_desc_remove_entry(struct page *page,
		struct kvm_rmap_desc *desc,
		int i, 
		struct kvm_rmap_desc *prev_desc)
{
	int j;

	for (j = RMAP_EXT - 1; !desc->shadow_ptes[j] && j > i; --j)
		;
	desc->shadow_ptes[i] = desc->shadow_ptes[j];
	desc->shadow_ptes[j] = NULL;
	if (j != 0)
		return;
	if (!prev_desc && !desc->more){
		set_page_private(page,(unsigned long)desc->shadow_ptes[0]);
	}else{
		if (prev_desc)
			prev_desc->more = desc->more;
		else
			set_page_private(page,(unsigned long)desc->more | 1);
	}
	mmu_free_rmap_desc(desc);
}

/*
 * rmap_remove
 * @spte
 * 
 * 
 */
void rmap_remove(u32 *spte)
{
	struct page *page;
	struct kvm_rmap_desc *desc;
	struct kvm_rmap_desc *prev_desc;
	int i;

	if (!is_rmap_pte(*spte)) 
		return;

	page = pfn_to_page((*spte & PAGE_MASK) >> PAGE_SHIFT);

	if (!page_private(page)) {
		return;
	} else if (!(page_private(page) & 1)) {
		set_page_private(page,0);
	} else {
		desc = (struct kvm_rmap_desc *)(page_private(page) & ~1ul);
		prev_desc = NULL;
		while (desc) {
			for (i = 0; i < RMAP_EXT && desc->shadow_ptes[i]; ++i){
				if (desc->shadow_ptes[i] == spte) {
					rmap_desc_remove_entry(page, desc, i, prev_desc);
					return;
				}
			}
			prev_desc = desc;
			desc = desc->more;
		}
	}
}

/*
 * rmap_write_protect
 * @vcpu
 * @gfn
 * 
 * 
 */
void rmap_write_protect(struct kvm_vcpu *vcpu, u32 gfn)
{
	struct page *page;
	struct kvm_rmap_desc *desc;
	u32 *spte;
	u32 value;

	page = gfn_to_page(vcpu->kvm, gfn); 

	while (page_private(page)) {
		if (!(page_private(page) & 1))
			spte = (u32 *)page_private(page);
		else {
			desc = (struct kvm_rmap_desc *)(page_private(page) & ~1ul);
			spte = desc->shadow_ptes[0];
		}
		rmap_remove(spte);

		// set spte RO:RO
		value = (*spte) & (~PTE_EXT_APX); 
		value |= PTE_EXT_AP1;
		value &= ~PTE_EXT_AP0;
		fill_spte(spte, value);
	}
}

/*
 * fill_spde - fill shadow page directory entry
 * @entry
 * @value
 */
inline void fill_spde(u32 *entry, u32 value)
{
	*entry = value;
	flush_pmd_entry((pmd_t *)entry);
}

/*
 * fill_spte - fill shadow page table entry
 * @entry
 * @value
 */
inline void fill_spte(u32 *entry, u32 value)
{
	*entry = value;
	flush_pmd_entry((pmd_t *)entry);
}

/*
 * get_guest_mode - return the guest vcpu mode
 * @vcpu
 */
int get_guest_mode(struct kvm_vcpu *vcpu)
{
	int mode = vcpu->arch.virtual_cpsr & 0x1f;
	if (mode == USR_MODE)
		return USER;
	else 
		return KERNEL;
}

/*
 * mmu_lookup_spage - find out a match shadow page
 * @vcpu
 * @gfn: as an index for iterate over list
 * @spt_type: type of the shadow page table: ROOT, PT, and etc.
 */
struct kvm_mmu_spage* mmu_lookup_spage(struct kvm_vcpu *vcpu, 
	gfn_t gfn, u8 spt_type)
{
	int index;
	struct kvm_mmu_spage *spage;
	struct hlist_head *bucket;
	struct hlist_node *node;

	index = gfn % KVM_NUM_MMU_SPAGES;
	bucket = &vcpu->kvm->arch.mmu_spage_hash[index];

	hlist_for_each_entry(spage, node, bucket, hash_link)
		if (spage->gfn == gfn && spage->spt_type == spt_type) 
			return spage;
	return NULL;	
}

/*
 * mmu_lookup_pt_spage
 * @vcpu
 * @gfn
 * 
 * seach PT (1KB alignment)
 */
static struct kvm_mmu_spage* mmu_lookup_pt_spage(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvm_mmu_spage *spage;
	u32 pt_gfn = gfn << 2;
	spage = mmu_lookup_spage(vcpu, pt_gfn, PT);
	if(spage) return spage;
	return mmu_lookup_spage(vcpu, pt_gfn + 1, PT);
}

/*
 * mmu_lookup_root_spage
 * @vcpu
 * @gfn
 * 
 * search root (16KB Alignment)
 */
struct kvm_mmu_spage* mmu_lookup_root_spage(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	gfn = gfn >> 2;
	gfn = gfn << 2;
	return mmu_lookup_spage(vcpu, gfn, ROOT);
}

/*
 * mmu_lookup_one_spage
 * @vcpu
 * @gfn
 */
struct kvm_mmu_spage* mmu_lookup_one_spage(struct kvm_vcpu *vcpu, gfn_t gfn)
{
#ifndef CONFIG_MEM_OPT
	struct kvm_mmu_spage *spage;
	spage = mmu_lookup_pt_spage(vcpu, gfn);
	if(spage) return spage;
#endif	
	return mmu_lookup_root_spage(vcpu, gfn);
}

/*
 * setup_kvm_vector
 * @vcpu
 * 
 * Set up the mapping entry to the exception vector table at 0xffff0000, then
 * every trap in guest and host machine can be intercept by hyporvisor.
 */
static void setup_kvm_vector(struct kvm_vcpu *vcpu, u32 *root)
{
	u32 gva = 0xffff0000;
	int index = ROOT_INDEX(gva);
	u32 value = vcpu->arch.vector_pgd_entry;
	fill_spde(&root[index], value);
	return;
}

/*
 * mmu_alloc_root_table
 * @vcpu
 * @spage
 * 
 * Allocate 4 physical frame at once, and record the address of the first page
 * of the 4 consecutive page in spage->root.  
 */
static void mmu_alloc_root_table(struct kvm_vcpu *vcpu, struct kvm_mmu_spage *spage)
{
	struct page *page;
	u32 *table_ptr;

	page = alloc_pages(GFP_KERNEL, 2);
	table_ptr = page_address(page);
	if(!table_ptr) KVM_MMU_BUG();
	memset(table_ptr, 0, PAGE_SIZE*4);

	spage->root = table_ptr;
	setup_kvm_vector(vcpu, table_ptr);

	clean_dcache_area(table_ptr, PTRS_PER_PGD * sizeof(pgd_t));

	return;
}

/*
 * mmu_alloc_pt_table
 * @vcpu
 * @spage
 * 
 * 
 */
static void mmu_alloc_pt_table(struct kvm_vcpu *vcpu, struct kvm_mmu_spage *spage)
{
	u32 *table_ptr;
	table_ptr = mmu_memory_cache_alloc(&vcpu->arch.mmu_pt_cache, PT_SIZE);
	if(!table_ptr) KVM_MMU_BUG();
	spage->pt = table_ptr;

	clean_dcache_area(table_ptr, PTRS_PER_PTE * sizeof(pte_t));

	return;
}

/*
 * hash_add
 * @vcpu
 * @spage
 * 
 */
static inline void hash_add(struct kvm_vcpu *vcpu, struct kvm_mmu_spage *spage)
{
	int index;
	struct hlist_head *bucket;

	index = spage->gfn % KVM_NUM_MMU_SPAGES;
	bucket = &vcpu->kvm->arch.mmu_spage_hash[index];
	hlist_add_head(&spage->hash_link, bucket);
	return;
}

/*
 * mmu_alloc_spage - allocate a shdow page
 * @vcpu
 * @gfn: GFN of the page table
 * @spt_type: requested type of the shadow page table: ROOT, PT, and etc.
 * @parent_pte:
 * @map_gva
 */
struct kvm_mmu_spage* mmu_alloc_spage(struct kvm_vcpu *vcpu, gfn_t gfn, u8 spt_type, 
			u32 *parent_pte, gva_t map_gva)
{
	struct kvm_mmu_spage *spage = NULL;

	spage = mmu_lookup_spage(vcpu, gfn, spt_type);

	if(!spage) { 
		spage = mmu_memory_cache_alloc(&vcpu->arch.mmu_spage_header_cache, 
						sizeof *spage);
		if(!spage) KVM_MMU_BUG();
		spage->gfn = gfn;
		spage->spt_type = spt_type;
		list_add(&spage->mmu_link, &vcpu->kvm->arch.active_mmu_spages);
		hash_add(vcpu, spage);
	}
	
	switch(spt_type){
	case ROOT:
	case PSEUDO_ROOT:
		if(spage->root) return spage;
		mmu_alloc_root_table(vcpu, spage);
		if(spt_type == ROOT) {
			if(gfn != 4) {
				rmap_write_protect(vcpu, gfn);
				rmap_write_protect(vcpu, gfn+1);
				rmap_write_protect(vcpu, gfn+2);
				rmap_write_protect(vcpu, gfn+3);
			}
		}
		break;
	case PT:
	case PSEUDO_PT:
		if(spage->pt) { 
			if(spt_type == PT) {
				/*
				 * FIXME: particular assumption
				 *  PT would not be shared
				 */
#ifndef CONFIG_MEM_OPT				
				KVM_MMU_BUG();
#else				
				spage->parent_pte = parent_pte; 
#endif				
			}
			return spage;
		}
		mmu_alloc_pt_table(vcpu, spage);
		spage->pt_map = map_gva & PT_MAP_MASK;

		spage->parent_pte = parent_pte; 

#ifndef CONFIG_MEM_OPT				
		if(spt_type == PT) 
			rmap_write_protect(vcpu, gfn >> 2);
#endif			
		break;
	default:
		KVM_MMU_BUG();
		break;
	}
	return spage;	
}

/*
 * mmu_alloc_spage_pv
 * @vcpu
 * @gfn
 * 
 * only allocate user PT
 */
struct kvm_mmu_spage* mmu_alloc_spage_pv(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvm_mmu_spage *spage;

	spage = mmu_lookup_spage(vcpu, gfn, PT);

	if(!spage) { 
		spage = mmu_memory_cache_alloc(&vcpu->arch.mmu_spage_header_cache, 
						sizeof *spage);
		if(!spage) KVM_MMU_BUG();
		spage->gfn = gfn;
		spage->spt_type = PT;
		list_add(&spage->mmu_link, &vcpu->kvm->arch.active_mmu_spages);
		hash_add(vcpu, spage);
	}
	if(spage->pt) 
		return spage;
	mmu_alloc_pt_table(vcpu, spage);
	spage->pt_map = 0;
	spage->parent_pte = NULL;

	return spage;	
}

/*
 * clear_pt_rmap
 * @pt
 */
static inline void clear_pt_rmap(u32 *pt)
{
	int i;
	for (i = 0; i < PT_TABLE_ENTRY; ++i) {
		if(pt[i] == 0)
			continue;
		rmap_remove(&pt[i]);
	}
}

/*
 * reset_parent_ptes
 * @parent_pte
 */
static inline void reset_parent_ptes(u32 *parent_pte)
{
	if(!parent_pte)
		return;
	fill_spde(parent_pte, 0);
	return;
}

/*
 * free_kernel_pt
 * @pt
 * @parent_pte
 * @pt_map
 */
static inline void free_kernel_pt(u32 *pt, u32 *parent_pte, u32 pt_map)
{
	if(pt!=NULL){
		if(pt_map >= TASK_SIZE) 
			clear_pt_rmap(pt);
		reset_parent_ptes(parent_pte);
		kfree(pt);
	}
	return;

}

/*
 * free_user_pt
 * @pt
 * @parent_pte
 * 
 */
static inline void free_user_pt(u32 *pt, u32 *parent_pte)
{
	if(pt!=NULL) {
		reset_parent_ptes(parent_pte);
		kfree(pt);
	}
	return;
}

/*
 * mmu_zap_spage
 * @spage
 * 
 * Suppose we neet not to free pte_chain becuase when ROOT will be zapped,
 * its PTs are already zapped.
 */
void mmu_zap_spage(struct kvm_mmu_spage *spage)
{
	switch(spage->spt_type){
	case ROOT:
	case PSEUDO_ROOT:
		if(spage->root)
			__free_page(virt_to_page(spage->root));
		break;
	case PT:
		free_kernel_pt(spage->pt, spage->parent_pte, spage->pt_map);
		break;
	case PSEUDO_PT:
		free_kernel_pt(spage->pt, spage->parent_pte, spage->pt_map);
		break;
	default:
		KVM_MMU_BUG();
		break;
	}
		
	list_del(&spage->mmu_link);
	hlist_del(&spage->hash_link);
	kfree(spage);
	return;
}

/*
 * mmu_zap_all_spages
 * @kvm
 * 
 * 
 */
void mmu_zap_all_spages(struct kvm *kvm)
{
	struct kvm_mmu_spage *spage, *node;
	list_for_each_entry_safe(spage, node, &kvm->arch.active_mmu_spages, mmu_link)
		mmu_zap_spage(spage);
}

/*
 * handle_pt_fault
 * @vcpu
 * @gfn
 *
 * Search PT (1KB alignment) 
 */
int handle_pt_fault(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvm_mmu_spage *spage;
	int fault = 0;
	u32 pt_gfn = gfn << 2;
	spage = mmu_lookup_spage(vcpu, pt_gfn, PT);
	if(spage) {
		fault = 1;
		mmu_zap_spage(spage);
	}
	spage = mmu_lookup_spage(vcpu, pt_gfn + 1, PT);
	if(spage) {
		fault = 1;
		mmu_zap_spage(spage);
	}
	return fault;
}
