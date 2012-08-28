/**
 *  @emulate_arm.h
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

#ifndef __ARM_KVM_EMULATE_H__
#define __ARM_KVM_EMULATE_H__
#include <asm/ptrace.h>

#define TRANSFER_MODEBITS(x) ((x) == 0x1f ? 0 : (((x) >> 2 & 3) + ((x) & 3)))
#define SYNC_PSRF(psr, f) ((psr) = ((psr) & ~PSR_f) | ((f) & PSR_f))
#define TRANSFER_BITSEG(n, m, i) (((i) & ~(0xffffffff << ((m) + 1))) >> (n))

#define NOP 0xe1a00000
#ifdef CONFIG_CPU_OPT
#define FAST_TRAP_TABLE_SIZE 30

#define BT(x) do { if (kvmarm_bt(vcpu, x) == 0) \
			kvmarm_bt_print(instr, x); \
		} while(0)
#else
#define BT(x) 
static inline void kvmarm_fast_trap_bt(struct kvm_vcpu *vcpu, struct instruction *instr) {} 
static inline void clear_fast_trap_table() {}
#endif

struct instruction {
	u32 cond;
	u32 opcode;
	u32 Rd_index;
	u32 Rn_index;
	u32 imme;
	u32 opcode2;
	u32 s_data;
	enum emulation_result return_info;
};

struct mmu_test {
	u32 pre_mmu_on;
	u32 cur_mmu_on;
};

struct domain_test {
	u32 hw_dom_reg;
	u32 domain_g_kernel;
	u32 domain_g_user;
	u32 domain_g_io;
	u32 domain_g_table;
};

void sync_condition_code (struct kvm_vcpu *vcpu);
void modify_cpsr(struct kvm_vcpu *vcpu, u32 value);
void change_mode(struct kvm_vcpu *vcpu, u32 old_mode, u32 new_mode);

u32 load_banked_sp(struct kvm_vcpu *vcpu, u32 mode);
u32 load_banked_lr(struct kvm_vcpu *vcpu, u32 mode);
u32 load_banked_spsr(struct kvm_vcpu *vcpu, u32 mode);
void store_banked_sp(struct kvm_vcpu *vcpu, u32 mode, u32 value);
void store_banked_lr(struct kvm_vcpu *vcpu, u32 mode, u32 value);
void store_banked_spsr(struct kvm_vcpu *vcpu, u32 mode, u32 value);
void clear_fast_trap_table();

int emu_mrs_cpsr(struct instruction *instr, struct kvm_vcpu *vcpu);
int emu_mrs_spsr(struct instruction *instr, struct kvm_vcpu *vcpu);
int emu_msr_cpsr(u32 inst,struct kvm_vcpu *vcpu, u32 operand);
int emu_msr_spsr(u32 inst,struct kvm_vcpu *vcpu, u32 operand);
u32 shift_imm_generator(u32 inst, struct kvm_vcpu *vcpu);
int emu_data(struct instruction *instr, struct kvm_vcpu *vcpu);
int emu_ls_ldrex(struct instruction *instr, struct kvm_vcpu *vcpu, u32 inst);
int emu_ls_strex(struct instruction *instr, struct kvm_vcpu *vcpu, u32 inst);
int emu_ls_ldrh(struct instruction *instr, struct kvm_run *run, struct kvm_vcpu *vcpu, u32 inst);
int emu_ls_strh(struct instruction *instr, struct kvm_run *run, struct kvm_vcpu *vcpu, u32 inst);
int emu_ls_ldrsb(struct instruction *instr, struct kvm_run *run, struct kvm_vcpu *vcpu, u32 inst);
int emu_ls_ldrsh(struct instruction *instr, struct kvm_run *run, struct kvm_vcpu *vcpu, u32 inst);
int emu_ls_strd(struct instruction *instr, struct kvm_vcpu *vcpu, u32 inst);
u32 immediate_generator(u32 inst);
int emu_ls1(struct instruction *instr, u32 inst, struct kvm_run *run, struct kvm_vcpu *vcpu);
int emu_mls(struct kvm_run *run, struct kvm_vcpu *vcpu, struct instruction *instr, u32 inst);
int emu_mcr(struct instruction *instr, struct kvm_vcpu *vcpu);
int emu_mrc(struct instruction *instr, struct kvm_vcpu *vcpu);
int emu_mcrr(struct instruction *instr, struct kvm_vcpu *vcpu);
int emu_cps(u32 inst, struct kvm_vcpu *vcpu);

#endif /* __ARM_KVM_EMULATE_H__ */
