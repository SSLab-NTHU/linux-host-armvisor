/**
 *  @kvm_host.h
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

#ifndef __ARM_KVM_HOST_H__
#define __ARM_KVM_HOST_H__

#include <asm/kvm_asm.h>

#define KVM_MAX_VCPUS 1
#define KVM_MEMORY_SLOTS 32
	/* memory slots that does not exposed to userspace */
#define KVM_PRIVATE_MEM_SLOTS 4

#define KVM_COALESCED_MMIO_PAGE_OFFSET 1

/* We don't currently support large pages. */
#define KVM_HPAGE_GFN_SHIFT(x)  0
#define KVM_NR_PAGE_SIZES        1
#define KVM_PAGES_PER_HPAGE(x)      (1UL<<31)

#define INVALID_PAGE (~(hpa_t)0)

#ifdef DEBUG_SSLAB
#define ASSERT(x)                           \
do {                                    \
    if (!(x)) {                         \
        printk(KERN_EMERG "assertion failed %s: %d: %s\n",  \
               __FILE__, __LINE__, #x);             \
        BUG();                          \
    }                               \
} while (0)
#else
#define ASSERT(x) do { } while (0)
#endif

//bank index
#define USR 0
#define SYSTEM 0
#define FIQ 1
#define IRQ 2
#define SVC 3
#define ABORT 4
#define UND 5

struct kvm;
struct kvm_run;
struct kvm_vcpu;

enum mmu_reason {
    MMU_SPT,
    MMU_VECTOR,
    MMU_SHARED_ADDR,
    MMU_INJECT_FAULT,
    MMU_MMIO,
    MMU_FAILED,
    MMU_OK
};
extern spinlock_t kvm_lock;
extern struct list_head vm_list;

struct kvm_vm_stat {
   // u32 mmu_shadow_zapped;
   // u32 mmu_pte_write;
   // u32 mmu_pte_updated;
   // u32 mmu_pde_zapped;
   // u32 mmu_flooded;
   // u32 mmu_recycled;
   // u32 mmu_cache_miss;
   // u32 mmu_unsync;
    u32 remote_tlb_flush;
   // u32 lpages;
};

#define KVM_NR_MEM_OBJS 40

struct kvm_mmu_memory_cache {
	int nobjs;
	void *objects[KVM_NR_MEM_OBJS];
};

struct kvm_arch {
	unsigned int n_requested_mmu_pages;
	struct hlist_head mmu_spage_hash[32];
	/* Hash table of struct kvm_mmu_page.
	*/
	struct list_head active_mmu_spages;
	struct kvm_gic *vgic;
};

struct inst_hit {
	u32 pc;
	u32 count;
	struct inst_hit *next;
};

struct asm_profiling_info {
	u32 chmod_exits;
	u32 true_swi;
	u32 cache_inst;
	u32 sync_cond_to_hw;
	u32 sync_cond_from_hw;
};

struct kvm_vcpu_stat { 
	u32 handle_exit;
	u32 emu_inst;
	//CPU Profiling
	u32 cond_inst;
	u32 data_inst;
	u32 msr_inst;
	u32 mrs_inst;
	u32 cps_inst;
	u32 ls_inst;
	u32 mls_inst;
	u32 exp_inst;
	u32 copr_inst;
	u32 cache_inst;
	u32 tlb_inst;
	u32 int_trap;

	//Memory Profiling
	u32 pabt_exits;
	u32 dabt_exits;
	u32 total_dabt_trap;
	u32 total_pabt_trap;
	u32 true_dabt_trap;
	u32 true_pabt_trap;
	u32 pv_write_pte;
	u32 pv_free_pte;
	u32 data_translation_miss;
	u32 inst_translation_miss;
	u32 protection_fault;
	u32 mmio_trap;

	//APPENDIX
	u32 sync_from_opt;
	u32 sync_to_opt;
	struct inst_hit *mmio_info;
	struct inst_hit *copr_info;
	struct inst_hit *mcr_info;
	struct inst_hit *cps_info;
	struct inst_hit *msr_info;
	struct inst_hit *mrs_info;
	struct inst_hit *mls_info;
	struct inst_hit *data_info;
	struct asm_profiling_info *asm_info;
};

struct kvm_mmu {
	int (*handle_fault)(struct kvm_vcpu *vcpu, gva_t gva, u32 fault_type);
	void (*alloc_root)(struct kvm_vcpu *vcpu);
	void (*free)(struct kvm_vcpu *vcpu);
	void (*c15_reset_mmu)(struct kvm_vcpu *vcpu);
	void (*c15_reset_ttbr0)(struct kvm_vcpu *vcpu);
	void (*c15_reset_domain)(struct kvm_vcpu *vcpu, u32 guest_domain);
	gpa_t (*gva_to_gpa)(struct kvm_vcpu *vcpu, gva_t gva);
	gpa_t mmio_addr;
	hpa_t root_hpa;
	struct kvm_mmu_spage* root;
};

struct kvm_vcpu_arch{
	// guest state (User Mode)    
	u32 regs[16];
	u32 spsr;
	u32 guest_c5_data;
	u32 guest_c5_insn;
	u32 guest_c6_data;
	u32 ctxt_id;
	u32* vector_pt;
	u32 vector_pgd_entry; 
	u32 vector_gfn;
	int vector_protection;

	// host state (KVM Mode)
	u32 host_regs[16];
	u32 host_pgd_addr;
	u32 host_spsr;
	u32 host_cpsr;
	u32 host_ctxt_id;
    
	//virtual register

	// virtual regs [0:7] = regs[0:7]
	// virtual regs [8:12]
	u32 usr_regs[5];
	u32 fiq_regs[5];
	/* Banked registers.  */
	u32 banked_r13[6];
	u32 banked_r14[6];
	u32 banked_spsr[6];
	u32 virtual_cpsr;
	u32 cpsr;

	//System control coprocessor (cp15)
	struct {
		uint32_t c0_cpuid;
		uint32_t c0_cachetype;
		uint32_t c0_ccsid[16]; /* Cache size.  */
		uint32_t c0_clid; /* Cache level.  */
		uint32_t c0_cssel; /* Cache size selection.  */
		uint32_t c0_c1[8]; /* Feature registers.  */
		uint32_t c0_c2[8]; /* Instruction set registers.  */
		uint32_t c1_sys; /* System control register.  */
		uint32_t c1_coproc; /* Coprocessor access register.  */
		uint32_t c1_xscaleauxcr; /* XScale auxiliary control register.  */
		uint32_t c2_base0; /* MMU translation table base 0.  */
		uint32_t c2_base1; /* MMU translation table base 1.  */
		uint32_t c2_control; /* MMU translation table base control.  */
		uint32_t c2_mask; /* MMU translation table base selection mask.  */
		uint32_t c2_base_mask; /* MMU translation table base 0 mask. */
		uint32_t c2_data; /* MPU data cachable bits.  */
		uint32_t c2_insn; /* MPU instruction cachable bits.  */
		uint32_t c3; /* MMU domain access control register
				MPU write buffer control.  */
		uint32_t c5_insn; /* Fault status registers.  */
		uint32_t c5_data;
		uint32_t c6_region[8]; /* MPU base/size registers.  */
		uint32_t c6_insn; /* Fault address registers.  */
		uint32_t c6_data;
		uint32_t c9_insn; /* Cache lockdown registers.  */
		uint32_t c9_data;
		uint32_t c13_fcse; /* FCSE PID.  */
		uint32_t c13_context; /* Context ID.  */
		uint32_t c13_tls1; /* User RW Thread register.  */
		uint32_t c13_tls2; /* User RO Thread register.  */
		uint32_t c13_tls3; /* Privileged Thread register.  */
		uint32_t c15_cpar; /* XScale Coprocessor Access Register */
		uint32_t c15_ticonfig; /* TI925T configuration byte.  */
		uint32_t c15_i_max; /* Maximum D-cache dirty line index.  */
		uint32_t c15_i_min; /* Minimum D-cache dirty line index.  */
		uint32_t c15_threadid; /* TI debugger thread-ID.  */
	} cp15;

	//inject exception
	uint32_t pending_sync_exceptions;
	uint32_t pending_async_exceptions;

	//mmu virtualization
	struct kvm_mmu mmu;
	
	struct kvm_mmu_memory_cache mmu_rmap_desc_cache;
	struct kvm_mmu_memory_cache mmu_spage_header_cache;
	struct kvm_mmu_memory_cache mmu_pt_cache;

	//instruction emulation
	u32 swi_num;
	u32 mls_regs;
	u8  is_mls;
	u8  load_style;
	u8  store_style;
	u8  signed_flag;
	u32 write_addr;
	u32 write_val; 
	u8 io_gpr;

	//mmio
	gpa_t paddr_accessed;	
	int is_mmio_inst;

	//swi
	uint32_t trapped_inst;
	u32 guest_swi_vector_addr;
};

enum profiling_status {
	PROFILING_START,
	PROFILING_END
};

enum emulation_result {
	EMULATE_DONE,         /* no further processing */
	EMULATE_DO_MMIO,      /* kvm_run filled with MMIO request */
	EMULATE_FAIL,         /* can't emulate this instruction */
};

#ifdef CONFIG_PROFILE_PC
void kvm_profiling_pc(struct inst_hit **info_head, u32 pc);
#else
#define kvm_profiling_pc(head, pc) 
#endif

#ifdef CONFIG_PROFILE_COUNT
void kvm_profiling_count(u32 *instr);
#else
#define kvm_profiling_count(stat) 
#endif

#define KVM_BUG(num) do {printk("KVM Bug:%d ---------> %s function  \n",num ,__FUNCTION__);\
		         BUG();}while(0) 

#endif /* __ARM_KVM_HOST_H__ */
