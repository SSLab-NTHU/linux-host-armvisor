/******************************************************************************
 * @emulate_arm.c
 *
 * Generic arm (32-bit) instruction decoder and emulator.
 *
 *  This file includes the functions for handling traps from guest OS
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
 *
 * Copyright (c) 2009~2012  SSLab, NTHU
 *
 */

#include <linux/module.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_para.h>
//#include "vsoft_mmu.h"
#include "mmu.h"
#include "emulate_arm.h"
#include "vsoft_vcpu.h"
#include <asm/cacheflush.h>

#define OP2_LDR_1	0x9
#define OP2_STRB_1	0x4
#define OP2_LDRB_1	0x5
#define OP2_STR_1	0x8
#define OP2_LDRB_2	0xd
#define OP2_STRB_2	0xc
#define OP2_STR_2	0x0
#define OP2_LDR_2	0x1
#define OP2_STR_3	0xa
#define OP2_LDRB_3	0xf
#define OP2_LDR_3	0xb
#define OP2_STRB_3	0xe
#define OP2_STRT	0x2
#define OP2_LDRT	0x3
#define OP2_STRBT	0x6
#define OP2_LDRBT	0x7

#define OP2_STM1_1	0
#define OP2_STM1_2	1
#define OP2_LDM1_1	2
#define OP2_LDM1_2	3
#define OP2_STM1_3	4
#define OP2_STM1_4	5
#define OP2_LDM1_3	6
#define	OP2_STM2_1	8
#define OP2_STM2_2	9
#define OP2_LDM2_1	10
#define OP2_LDM3_1	11
#define OP2_LDM3_2	15

#define FIELD_MASK_0		16
#define FIELD_MASK_1		17
#define FIELD_MASK_2		18
#define FIELD_MASK_3		19
#define FIELD_NOT_PRIVILIGED	0x10

#define OP2_AND	0
#define OP2_EOR	1
#define OP2_SUB	2
#define OP2_RSB	3
#define OP2_ADD	4
#define OP2_ADC	5
#define OP2_SBC	6
#define OP2_RSC	7
#define OP2_ORR	12
#define OP2_MOV	13
#define OP2_BIC	14
#define OP2_MVN	15

#define MCR_CP15_C1	1
#define MCR_CP15_C2	2
#define MCR_CP15_C3	3
#define MCR_CP15_C5	5
#define MCR_CP15_C6	6
#define MCR_CP15_C7	7
#define MCR_CP15_C8	8
#define MCR_CP15_C9	9
#define MCR_CP15_C13	13
#define MCR_CP15_C15	15

#define MCR_CP15_C1_C0	0
#define MCR_CP15_C1_C1	1

#define OP2_CTRL_BT_TRAP		0
#define OP2_AUX_CTRL			1
#define OP2_COPROC_ACCESS_CTRL		2

#define OP2_SECURE_CONF			0
#define OP2_SECURE_DEBUG_ENABLE		1
#define OP2_NONSECURE_ACCESS_CTRL	2

#define MCR_CP15_C7_C0	0
#define MCR_CP15_C7_C5	5
#define MCR_CP15_C7_C6	6
#define MCR_CP15_C7_C7	7
#define MCR_CP15_C7_C10	10
#define MCR_CP15_C7_C11	11
#define MCR_CP15_C7_C13	13
#define MCR_CP15_C7_C14	14
#define MCR_CP15_C7_C15	15

#define OP2_MCR_WAIT_INTERRUPT	4

#define OP2_INVALID_ENTIRE_I_CACHE		0
#define OP2_INVALID_I_CACHE_LINE_MVA		1
#define OP2_INVALID_I_CACHE_LINE_SETWAY		2
#define OP2_FLUSH_PREFETCH_BUFFER		4
#define OP2_FLUSH_ENTIRE_BRANCH_TARGET_CACHE	6
#define OP2_FLUSH_BRANCH_TARGET_ENTRY		7

#define OP2_INVALID_ENTIRE_D_CACHE		0
#define OP2_INVALID_D_CACHE_LINE_MVA		1
#define OP2_INVALID_D_CACHE_LINE_SETWAY		2

#define OP2_INVALID_ID_CACHE_FLUSH_BRANCH_ENTRY	0

#define OP2_CLEAN_ENTIRE_D_CACHE	0
#define OP2_CLEAN_D_CACHE_LINE_MVA	1
#define OP2_CLEAN_D_CACHE_LINE_SETWAY	2

#define OP2_CLEAN_INVALID_ENTIRE_D_CACHE	0
#define OP2_CLEAN_INVALID_D_CACHE_LINE_MVA	1
#define OP2_CLEAN_INVALID_D_CACHE_LINE_SETWAY	2

#define MCR_CP15_C8_C5	5
#define MCR_CP15_C8_C6	6
#define MCR_CP15_C8_C7	7

#define OP2_INVALID_I_TLB_UNLOCKED_ENTRY	0
#define OP2_INVALID_I_TLB_ENTRY_MVA		1
#define OP2_INVALID_I_TLB_ENTRY_ASID_MATCH	2
#define OP2_INVALID_I_TLB_SINGLE_ENTRY_MVA	3

#define OP2_INVALID_D_TLB_UNLOCKED_ENTRY	0
#define OP2_INVALID_D_TLB_ENTRY_MVA		1
#define OP2_INVALID_D_TLB_ENTRY_ASID_MATCH	2
#define OP2_INVALID_D_TLB_SINGLE_ENTRY_MVA	3

#define OP2_INVALID_UTLB_UNLOCKED_ENTRY		0
#define OP2_INVALID_UTLB_ENTRY_MVA		1
#define OP2_INVALID_UTLB_ASID_MATCH		2
#define OP2_INVALID_UTLB_SINGLE_ENTRY_MVA	3

#define OP2_CONTEXT_ID	1

#define MLS_DA	0
#define MLS_IA	1
#define MLS_DB	2
#define MLS_IB	3

int special_cond(struct instruction *, struct kvm_vcpu *);

/**
  * @brief sync PSR_f from native cpsr, PSR_f is PSR & 0xff000000.
  */
inline void sync_condition_code (struct kvm_vcpu *vcpu)
{
	SYNC_PSRF(vcpu->arch.virtual_cpsr, vcpu->arch.spsr);
}


#ifdef CONFIG_CPU_OPT
int kvmarm_bt(struct kvm_vcpu *vcpu, u32 inst)
{
	u32 gva, hva;
	gfn_t gfn;
	gpa_t gpa;

	gva = vcpu->arch.regs[15] - 4;
	__cpuc_coherent_user_range(gva, gva);

	gpa = vcpu->arch.mmu.gva_to_gpa(vcpu, gva);
	gfn = gpa >> PAGE_SHIFT;
	hva = gfn_to_hva(vcpu->kvm, gfn) + offset_in_page(gpa);

	kvm_write_guest(vcpu->kvm, gpa, &inst, 4);

	__cpuc_coherent_kern_range(hva, hva);
	return 0;
}

void kvmarm_bt_print(struct instruction *instr, u32 inst)
{
	printk("--Binary Translator: mcr, p15, 0, c%d, c%d, %d -> %x\n",
		instr->Rn_index, instr->imme, instr->opcode2, inst);
}

void kvmarm_fast_trap_bt(struct kvm_vcpu *vcpu, struct instruction *instr)
{
	struct fast_trap_entry *table = 0xffff1874;
	int i, found;
	u32 inst = vcpu->arch.trapped_inst;
	u32 swine = 0x1f000198;
	u32 swi = 0xef000198;

	instr->cond = vcpu->arch.trapped_inst >> 28 & 0xF;
	inst = (inst & 0x0fffffff) | 0xe0000000;

	found = 0;
	for (i = 0; i < FAST_TRAP_TABLE_SIZE; i ++) {
		if ((table+i)->pc == 0) break;
		if ((table+i)->pc == vcpu->arch.regs[15]) {
			found = 1;
			printk("=== FAST TRAP TABLE HIT ===  pc->%x\n", vcpu->arch.regs[15]);
			(table+i)->inst = inst;
			break;
		}
	}

	if (i >= FAST_TRAP_TABLE_SIZE)
		return ;

	if (found == 0) {
		(table+i)->pc = vcpu->arch.regs[15];
		(table+i)->inst = inst;
	}

	printk("table size : %d pc : %x\n", i, vcpu->arch.regs[15]);

	if (instr->cond == 1) //NE
		BT(swine);
	else
		BT(swi);
}

void clear_fast_trap_table()
{
	struct fast_trap_entry *table = 0xffff1874;
	int i;

	for (i = 0; i < FAST_TRAP_TABLE_SIZE; i ++) {
		(table+i)->pc = 0;
		(table+i)->inst = 0;
	}
}
#endif

void kvmarm_return_undefine()
{
	return;
}

//sync condition code to native cpsr
//not only condition code but also mode bit
void modify_cpsr(struct kvm_vcpu *vcpu, u32 value)
{
	u32 old_mode, new_mode;

	old_mode = TRANSFER_MODEBITS(vcpu->arch.virtual_cpsr & MODE_MASK);

	vcpu->arch.virtual_cpsr = value;
	new_mode = TRANSFER_MODEBITS(vcpu->arch.virtual_cpsr & MODE_MASK);

	if (old_mode != new_mode)
		change_mode(vcpu, old_mode, new_mode);

	//sync PSR_f
	SYNC_PSRF(vcpu->arch.spsr, vcpu->arch.virtual_cpsr);
}

inline u32 load_banked_spsr(struct kvm_vcpu *vcpu, u32 mode)
{
	u32 spsr = 0;

	if (mode != USR && mode != SYSTEM)
		spsr = vcpu->arch.banked_spsr[mode];
	else
		KVM_BUG(1);

	return spsr;
}

inline void store_banked_spsr(struct kvm_vcpu *vcpu, u32 mode, u32 value)
{
	if (mode != USR && mode != SYSTEM)
		vcpu->arch.banked_spsr[mode] = value;
	else
		KVM_BUG(1);
}

inline u32 load_banked_sp(struct kvm_vcpu *vcpu, u32 mode)
{
	if (mode == SVC)
		sync_from_opt_regs(VIRT_SVC_SP, vcpu);
	else if (mode == USR)
		sync_from_opt_regs(VIRT_USR_SP, vcpu);

	return vcpu->arch.banked_r13[mode];
}

inline void store_banked_sp(struct kvm_vcpu *vcpu, u32 mode, u32 value)
{
	vcpu->arch.banked_r13[mode] = value;
	if (mode == SVC)
		sync_to_opt_regs(VIRT_SVC_SP, vcpu);
	else if (mode == USR)
		sync_to_opt_regs(VIRT_USR_SP, vcpu);
}

inline u32 load_banked_lr(struct kvm_vcpu *vcpu, u32 mode)
{
	if (mode == SVC)
		sync_from_opt_regs(VIRT_SVC_LR, vcpu);
	else if (mode == USR)
		sync_from_opt_regs(VIRT_USR_LR, vcpu);
	return vcpu->arch.banked_r14[mode];
}

inline void store_banked_lr(struct kvm_vcpu *vcpu, u32 mode, u32 value)
{
	vcpu->arch.banked_r14[mode] = value;
	if (mode == SVC)
		sync_to_opt_regs(VIRT_SVC_LR, vcpu);
	else if (mode == USR)
		sync_to_opt_regs(VIRT_USR_LR, vcpu);
}

void switch_bank_register(struct kvm_vcpu* vcpu, u32 old_mode, u32 new_mode)
{
	int i;
	if (old_mode == FIQ) {
		for (i = 8; i <= 12; i++) {
			vcpu->arch.fiq_regs[i-8] = vcpu->arch.regs[i];
			vcpu->arch.regs[i] =vcpu->arch.usr_regs[i-8];
		}
	} else if (new_mode == FIQ) {
		for (i = 8; i <= 12; i++) {
			vcpu->arch.usr_regs[i-8] = vcpu->arch.regs[i];
			vcpu->arch.regs[i] = vcpu->arch.fiq_regs[i-8];
		}
	}

	store_banked_sp(vcpu, old_mode, vcpu->arch.regs[13]);
	vcpu->arch.regs[13] = load_banked_sp(vcpu, new_mode);

	store_banked_lr(vcpu, old_mode, vcpu->arch.regs[14]);
	vcpu->arch.regs[14] = load_banked_lr(vcpu, new_mode);
}

void change_mode(struct kvm_vcpu *vcpu, u32 old_mode, u32 new_mode)
{
	switch_bank_register(vcpu, old_mode, new_mode);
	c15_reset_domain(vcpu, vcpu->arch.cp15.c3);
}


u32 shift_imm(u32 inst, u32 index, struct kvm_vcpu *vcpu)
{
	u32 shift_imm = TRANSFER_BITSEG(7, 11, inst);
	u32 flag_C;
	
	switch (TRANSFER_BITSEG(5, 6, inst)) {
	case 0://0
		//LSL
		index = index << shift_imm;
		return index;
	case 1://1
		//LSR
		index = index >> shift_imm;
		return index;
	case 2://2
		//ASR
		/*
		if (shift_imm == 0) {
			if (test_bit(31, (void*)&index)) {
				index = 0xffffffff;
			} else {
				index = 0;
			}
		} else {
			if (!test_bit(31, (void*)&index))
				index = index >> shift_imm;
			else {
				for(i = 0; i < shift_imm; i++)
					temp_operand += (1 << (31-i));
				printk("temp_operand =0x%x\n",temp_operand);
				printk("index = 0x%x\n",index);
				index = (index >> shift_imm) | temp_operand;
			}
		}
		*/
		index = (int)index >> shift_imm;
		return index;
	case 3://3
		//ROR or RRX maybe have a problem;
		if (shift_imm == 0) {
			flag_C = test_bit(29, (void*)&vcpu->arch.virtual_cpsr) << 31;
			index = (index >> 1) | flag_C;
		} else {
			index = ((index) >> (shift_imm)) | ((index) << (32 - (shift_imm)));
		}
		return index;
	default:
		KVM_BUG(1);
	}
}

u32 rotate_right_extend(u32 index, u32 shift_imm, struct kvm_vcpu *vcpu)
{
	u32 flag_C = test_bit(29, (void*)&vcpu->arch.virtual_cpsr) << 31;
	index = (index >> 1) | flag_C;	
	return index;
}

u32 rotate_right(u32 index, int shift_imm)
{
	index = ((index) >> (shift_imm)) | ((index) << (32 - (shift_imm)));
	return index;
}

u32 arithmetic_right(u32 index, u32 shift_imm)
{
	int i;
	u32 temp_operand = 0;
	if (!test_bit(31, (void*)&index))
		index = index >> shift_imm;
	else {
		for (i = 0; i < shift_imm; i++)
			temp_operand += (1 << (31-i));
		index = (index >> shift_imm) | temp_operand;
	}
	return index;
}

u32 shift_imm_generator(u32 inst, struct kvm_vcpu *vcpu)
{
	u32 b6_4 = TRANSFER_BITSEG(4, 6, inst);
	u32 b7_4 = TRANSFER_BITSEG(4, 7, inst);
	u32 shifter_operand;
	u32 shift_imm = TRANSFER_BITSEG(7, 11, inst);
	u32 rs_index = TRANSFER_BITSEG(8, 11, inst);
	u32 rs_data = vcpu->arch.regs[rs_index];
	u32 rs7_0 = rs_data % 0x00000100;
	u32 rs4_0 = rs_data % 0x000000020;
	u32 rm_index = TRANSFER_BITSEG(0, 3, inst);
	u32 rm_data = vcpu->arch.regs[rm_index];
	
	if (b6_4 == 0)
	{
		if (shift_imm ==0) {
			shifter_operand = vcpu->arch.regs[rm_index];
		} else {
			KVM_BUG(1);
			rm_data = rm_data << shift_imm;
			shifter_operand = rm_data;
		}
	} else if (b7_4 == 1) {
		KVM_BUG(1);		
		if (rs7_0 == 0) {
			shifter_operand = rm_data;
		} else if (rs7_0 < 32) {
			rm_data = rm_data << rs7_0;
			shifter_operand = rm_data;
		} else if (rs7_0 == 32) {
			shifter_operand = 0;
		} else {
			shifter_operand = 0;
		}
	} else if (b6_4 == 2) {
		KVM_BUG(1);
		if (shift_imm == 0) {
			shifter_operand = 0;
		} else {
			rm_data = rm_data >> shift_imm;	
			shifter_operand = rm_data;
		}
	} else if (b7_4 == 3) {
		KVM_BUG(1);
		if (rs7_0 == 0) {
			shifter_operand = rm_data;
		} else if (rs7_0 < 32) {
			rm_data = rm_data >> rs7_0;
			shifter_operand = rm_data;
		} else if (rs7_0 == 32) {
			shifter_operand = 0;
		} else {
			shifter_operand = 0;
		}
	} else if (b6_4 == 4) {
		KVM_BUG(1);
		if (shift_imm == 0) {
			if (!(rm_data / 0x80000000))
				shifter_operand = 0;
			else
				shifter_operand = 0xffffffff;
		} else if (shift_imm > 0) {
			rm_data = arithmetic_right(rm_data, shift_imm);
			shifter_operand = rm_data;
		}
	} else if (b7_4 == 5) {
		KVM_BUG(1);
		if (rs7_0 == 0) {
			shifter_operand = rm_data;
		} else if (rs7_0 < 32) {
			rm_data = arithmetic_right(rm_data, rs7_0);
			shifter_operand = rm_data;
		} else {
			if (!(rm_data / 0x80000000))
				shifter_operand = 0;
			else
				shifter_operand = 0xffffffff;
		}
	} else if (b6_4 == 6) {
		KVM_BUG(1);
		if (shift_imm == 0) {
			shifter_operand = rm_data;
			shifter_operand =rotate_right_extend(shifter_operand,0,vcpu);
		} else {	
			rm_data = rotate_right(rm_data,shift_imm);
			shifter_operand = rm_data;
		}
	} else if (b7_4 == 7) {
		KVM_BUG(1);
		if (rs7_0 == 0) {
			shifter_operand = rm_data;
		} else if (rs4_0 == 0) {
			shifter_operand = rm_data;
		} else {
			rm_data = rotate_right(rm_data,rs4_0);
			shifter_operand = rm_data;
		}
	}
	return shifter_operand;
}

u32 immediate_generator(u32 inst)
{
	u32 rotate_imm = TRANSFER_BITSEG(8, 11, inst);
	u32 immed_8 = TRANSFER_BITSEG(0, 7, inst);
	u32 rotate_count = rotate_imm << 1;
	u32 shifter_operand = (immed_8 >> rotate_count) | (immed_8 << (32 - rotate_count));
	return shifter_operand;
}

void LS_sh_update_base_addr(u32 inst, struct kvm_vcpu *vcpu)
{
	u32 rn_index = TRANSFER_BITSEG(16, 19, inst);
	u32 immed_H,immed_L,offset_8;
	u32 rm_index = TRANSFER_BITSEG(0, 3, inst); 
	immed_L = TRANSFER_BITSEG(0, 3, inst);
	immed_H = TRANSFER_BITSEG(8, 11, inst);
	offset_8 = immed_H << 4 | immed_L;

	switch (TRANSFER_BITSEG(21, 24, inst)) {
	case 0:
		KVM_BUG(1);
		vcpu->arch.regs[rn_index] = vcpu->arch.regs[rn_index] - vcpu->arch.regs[rm_index];
		break;
	case 2:
		KVM_BUG(1);
		vcpu->arch.regs[rn_index] = vcpu->arch.regs[rn_index] - offset_8;
		break;
	case 4:
		KVM_BUG(1);
		vcpu->arch.regs[rn_index] = vcpu->arch.regs[rn_index] + vcpu->arch.regs[rm_index];
		break;
	case 6:
		KVM_BUG(1);
		vcpu->arch.regs[rn_index] = vcpu->arch.regs[rn_index] + offset_8;
		break;
	}

	if (test_bit(24, (void*)&inst)) {
		if (test_bit(21, (void*)&inst)) {
			KVM_BUG(2);
			vcpu->arch.regs[rn_index] = vcpu->arch.cp15.c6_data;
		}
	}
}

u32 get_address(struct instruction *instr, u32 inst, struct kvm_vcpu *vcpu)
{
	u32 offset_12, addr = 0;
	u32 rn_data = vcpu->arch.regs[instr->Rn_index];
	u32 rm_index, rm_data,index;
	u32 u_3 = TRANSFER_BITSEG(23, 25, inst);

	if (u_3 == 3) {
		//addr = rn + offset_12
		offset_12 = TRANSFER_BITSEG(0, 11, inst);
		addr = rn_data + offset_12;
	} else if (u_3 == 2) {
		//addr = rn - offset_12;
		offset_12 = TRANSFER_BITSEG(0, 11, inst);
		addr = rn_data - offset_12;
	} else if (u_3 == 7) {
		if (TRANSFER_BITSEG(4, 11, inst) == 0) {
			//addr = rn + rm
			rm_index = TRANSFER_BITSEG(0, 3, inst);
			rm_data = vcpu->arch.regs[rm_index];
			addr = rn_data + rm_data;
		} else {
			//addr = rn + rm shift imm
			rm_index = TRANSFER_BITSEG(0, 3, inst);
			index = vcpu->arch.regs[rm_index];
			index = shift_imm(inst, index, vcpu);
			addr = rn_data + index;
		}
	} else if (u_3 == 6) {
		if (TRANSFER_BITSEG(4, 11, inst) == 0) {
			//addr = rn - rm
			rm_index = TRANSFER_BITSEG(0, 3, inst);
			rm_data = vcpu->arch.regs[rm_index];
			addr = rn_data - rm_data;
		} else {
			//addr = rn - rm shift imm
			rm_index = TRANSFER_BITSEG(0, 3, inst);
			index = vcpu->arch.regs[rm_index];
			index = shift_imm(inst, index, vcpu);
			addr = rn_data - index;
		}
	}

	if (test_bit(21, (void*)&inst)) {
		vcpu->arch.regs[instr->Rn_index] = addr;
	}

	/***********post addressing*********/
	if (u_3 == 1) {
		//addr = rn
		//if(cond)
		//rn = rn + offset_12
		addr = rn_data;
		offset_12 = TRANSFER_BITSEG(0, 11, inst);
		vcpu->arch.regs[instr->Rn_index] = rn_data+offset_12;
	} else if (u_3 == 0) {
		//addr = rn
		//if(cond)
		//rn = rn -offset_12
		addr = rn_data;
		offset_12 = TRANSFER_BITSEG(0, 11, inst);
		vcpu->arch.regs[instr->Rn_index] = rn_data - offset_12;
	} else if (u_3 == 4) {	
		KVM_BUG(1);
		//addr = rn
		//if(cond)
		//rn = rn - rm or rn = rn - rm shift imm
		addr = rn_data;

		rm_index = TRANSFER_BITSEG(0, 3, inst);
		rm_data = vcpu->arch.regs[rm_index];
		if (TRANSFER_BITSEG(4, 11, inst) == 0) {
			vcpu->arch.regs[instr->Rn_index] = rn_data - rm_data;   
			//write_banked_regs(vcpu, rn_index, rn_data - rm_data);
		} else {
			//shift rm here
			//	rm_index = this->BITS(instr,0,3);
			//	Register_32bit & rm = this->get_register(rm_index);
			index = vcpu->arch.regs[rm_index];
			index = shift_imm(inst, index, vcpu);
			vcpu->arch.regs[instr->Rn_index] = rn_data - index;
		}
	} else if (u_3 == 5) {
		KVM_BUG(1);
		//addr = rn 
		//if(cond)
		//rn = rn + rm or rn = rn + rm shift imm
		addr = rn_data;
		rm_index = TRANSFER_BITSEG(0, 3, inst);
		rm_data = vcpu->arch.regs[rm_index];
		if (TRANSFER_BITSEG(4, 11, inst) == 0) {
			vcpu->arch.regs[instr->Rn_index] = rn_data + rm_data;
			//write_banked_regs(vcpu,rn_index,rn_data + rm_data);
		} else {
			//shift rm here
			//      rm_index = this->BITS(instr,0,3);
			//      Register_32bit & rm = this->get_register(rm_index);
			index = vcpu->arch.regs[rm_index];
			index = shift_imm(inst, index, vcpu);
			vcpu->arch.regs[instr->Rn_index] = rn_data + index;
		}
	}
	return addr;
}

int bit_num(u32 inst, int start, int end)
{
	int i, bit, num;
	num = 0;
	bit = 1 << start;
	for (i = start; i <= end; i++) {
		if ( inst & bit )
			num++;
		bit = bit << 1;
	}
	return num;
}

/**
  * @brief multi_address is changing to MLS addressing mode. And update the address. 
  */
u32 multi_address(struct instruction *instr, u32 *start_address, u32 *end_address, u32 inst, struct kvm_vcpu *vcpu)
{
	u32 rn_data = vcpu->arch.regs[instr->Rn_index];
	int num = bit_num(inst, 0, 15);
	u32 value;

	switch (TRANSFER_BITSEG(23, 24, inst)) {
	case MLS_DA:
		KVM_BUG(2);
		*end_address = rn_data;
		*start_address = *end_address + 4 - num * 4;
		value = *start_address - 4;
		*start_address = *start_address & 0xfffffffc;
		*end_address = *end_address & 0xfffffffc;
		break;

	case MLS_IA:
		*start_address = rn_data;
		*end_address = *start_address + num * 4 - 4;
		value = rn_data + num * 4;
		*start_address = *start_address & 0xfffffffc;
		*end_address = *end_address & 0xfffffffc;
		break;

	case MLS_DB:
		*end_address = rn_data - 4;
		*start_address = *end_address + 4 - num * 4;
		value = *end_address + 4 - num * 4;
		*start_address = *start_address & 0xfffffffc;
		*end_address = *end_address & 0xfffffffc;
		break;

	case MLS_IB:
		KVM_BUG(1);
		*start_address = rn_data + 4;
		*end_address = *start_address - 4 + num * 4;
		value = rn_data + num * 4;
		*start_address = *start_address & 0xfffffffc;
		*end_address = *end_address & 0xfffffffc;
		break;

	default:
		KVM_BUG(3);
	}

	if (test_bit(21, (void*)&inst)) {
		vcpu->arch.regs[instr->Rn_index] = value;
	}
	return rn_data;
}

int kvmarm_handle_mul_load(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 start_address, u32 end_address, u8 load_style)
{
	u32 gpa = vcpu->arch.mmu.gva_to_gpa(vcpu, start_address);
	run->mmio.phys_addr = gpa;
	run->mmio.len = end_address - start_address + 4;
	run->mmio.is_write = 0;
	vcpu->arch.mls_regs = vcpu->arch.trapped_inst & 0xffff;
	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = 0;
	vcpu->arch.load_style = load_style;
	vcpu->arch.is_mls = 1;
	return EMULATE_DO_MMIO;
}

int kvmarm_handle_mul_store(struct kvm_run *run, struct kvm_vcpu *vcpu, struct instruction *instr, u32 start_address, u32 end_address, u8 store_style, u32 origin_rn)
{
	int i;
	u8 *data = run->mmio.data;

	run->mmio.phys_addr = vcpu->arch.paddr_accessed;
	run->mmio.is_write = 1;
	run->mmio.len = end_address -start_address + 4;
	vcpu->arch.mls_regs = vcpu->arch.trapped_inst & 0xffff;
	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = 1;
	vcpu->arch.is_mls = 1;
	vcpu->arch.store_style = store_style;
	if (store_style == 1) {
		for (i = 0; i <= 15; i++) {
			if (test_bit(i, (void*)&vcpu->arch.mls_regs)) {
				if (i == 15) {
					*(u32 *)data = vcpu->arch.regs[i] + 4;
				} else {
					if (i == instr->Rn_index)
						*(u32 *)data = origin_rn;
					else
						*(u32 *)data = vcpu->arch.regs[i];
				}
				data = data + 4;
			}
		}
	} else {
		for (i = 0; i <= 7; i++) {
			if (test_bit(i, (void*)&vcpu->arch.mls_regs)) {
				if (i == instr->Rn_index)
					*(u32 *)data = origin_rn;
				else
					*(u32 *)data = vcpu->arch.regs[i];
				data = data + 4;
			}
		}
		for (i = 8; i <= 12; i++) {
			if (test_bit(i, (void*)&vcpu->arch.mls_regs)) {
				*(u32 *)data = vcpu->arch.usr_regs[i-8];
				data = data + 4;
			}
		}
		if (test_bit(13, (void*)&vcpu->arch.mls_regs)) {
			*(u32 *)data = load_banked_sp(vcpu, USR);
			data = data + 4;
		}
		if (test_bit(14, (void*)&vcpu->arch.mls_regs)) {
			*(u32 *)data = load_banked_lr(vcpu, USR);
			data = data + 4;
		}
		if (test_bit(15, (void*)&vcpu->arch.mls_regs)){
			*(u32 *)data = vcpu->arch.regs[15] + 4;
			data = data + 4;
		}
	}
	return EMULATE_DO_MMIO;
}

int kvmarm_handle_guest_ldm2(struct kvm_vcpu *vcpu, u32 start_address)
{
	u32 gpa = vcpu->arch.mmu.gva_to_gpa(vcpu, start_address);
	u32 mode_bits = vcpu->arch.virtual_cpsr & MODE_MASK;
	u32 value;
	int i;
	vcpu->arch.mls_regs = vcpu->arch.trapped_inst & 0xffff;

	if (mode_bits == USR_MODE) KVM_BUG(1);

	//regs[0-7]
	for (i = 0; i <= 7; i++) {
		if (test_bit(i, (void*)&vcpu->arch.mls_regs)) {
			kvm_read_guest(vcpu->kvm, gpa, &value, 4);
			vcpu->arch.regs[i] = value;
			gpa = gpa + 4;
		}
	}

	//regs[8-12]
	if (mode_bits != FIQ_MODE) {
		for (i = 8; i <= 12; i++) {
			if (test_bit(i, (void*)&vcpu->arch.mls_regs)) {
				kvm_read_guest(vcpu->kvm, gpa, &value, 4);
				vcpu->arch.regs[i] = value;
				gpa = gpa + 4;
			}
		}
	} else {
		for (i = 8; i <= 12; i++) {
			if(test_bit(i, (void*)&vcpu->arch.mls_regs)){
				kvm_read_guest(vcpu->kvm, gpa, &value, 4);
				vcpu->arch.usr_regs[i-8] = value;
				gpa = gpa + 4;
			}
		}
	}

	//regs[13,14]
	if (test_bit(13, (void*)&vcpu->arch.mls_regs)) {
		kvm_read_guest(vcpu->kvm, gpa, &value, 4);
		store_banked_sp(vcpu, USR, value);
		gpa = gpa + 4;
	}
	if (test_bit(14, (void*)&vcpu->arch.mls_regs)) {
		kvm_read_guest(vcpu->kvm, gpa, &value, 4);
		store_banked_lr(vcpu, USR, value);
		gpa = gpa + 4;
	}

	return EMULATE_DONE;
}

int kvmarm_handle_guest_ldm3(struct kvm_vcpu *vcpu, u32 start_address)
{
	u32 gpa = vcpu->arch.mmu.gva_to_gpa(vcpu, start_address);
	u32 mode = TRANSFER_MODEBITS(vcpu->arch.virtual_cpsr & MODE_MASK);
	u32 value;
	int i;
	u32 tmp_cpsr;
	vcpu->arch.mls_regs = vcpu->arch.trapped_inst & 0xffff;

	if (mode == USR) KVM_BUG(1);

	for (i = 0; i <= 15; i++) {
		if (test_bit(i, (void*)&vcpu->arch.mls_regs)) {
			kvm_read_guest(vcpu->kvm, gpa, &value, 4);
			vcpu->arch.regs[i] = value;
			gpa = gpa + 4;
		}
	}

	tmp_cpsr = load_banked_spsr(vcpu, mode);
	modify_cpsr(vcpu, tmp_cpsr);

	return EMULATE_DONE;
}

int kvmarm_handle_guest_stm(struct instruction *instr, struct kvm_vcpu *vcpu, u32 start_address, u32 origin_rn)
{
	u32 gpa = vcpu->arch.mmu.gva_to_gpa(vcpu, start_address); 
	u32 tmp_pc;
	u32 value;
	int i;

	vcpu->arch.mls_regs = vcpu->arch.trapped_inst & 0xffff;

	for (i = 0; i <= 14; i++) {
		if (test_bit(i, (void*)&vcpu->arch.mls_regs)) {

			if(i == instr->Rn_index)
				value = origin_rn;
			else
				value = vcpu->arch.regs[i];

			kvm_write_guest(vcpu->kvm, gpa, &value, 4);
			gpa = gpa + 4;
		}
	}

	if (test_bit(15, (void*)&vcpu->arch.mls_regs)) {
		tmp_pc = vcpu->arch.regs[15] + 4;
		kvm_write_guest(vcpu->kvm, gpa, &tmp_pc, 4);
		gpa = gpa + 4;
	}

	return EMULATE_DONE;
}


int kvmarm_handle_guest_stm2(struct instruction *instr, struct kvm_vcpu *vcpu, u32 start_address, u32 origin_rn)
{
	u32 gpa = vcpu->arch.mmu.gva_to_gpa(vcpu,start_address); 
	u32 mode_bits = vcpu->arch.virtual_cpsr & MODE_MASK;
	u32 tmp_pc;
	u32 banked_sp, banked_lr;
	int i;

	vcpu->arch.mls_regs = vcpu->arch.trapped_inst & 0xffff;

	if (mode_bits == USR_MODE) KVM_BUG(1);

	for (i = 0; i <= 7; i++) {
		if (test_bit(i, (void*)&vcpu->arch.mls_regs)) {
			if(i == instr->Rn_index)
				kvm_write_guest(vcpu->kvm, gpa, &origin_rn, 4);
			else
				kvm_write_guest(vcpu->kvm, gpa, &vcpu->arch.regs[i], 4);
			gpa = gpa + 4;
		}
	}

	if (mode_bits != FIQ_MODE) {
		for (i = 8; i <= 12; i++) {
			if (test_bit(i, (void*)&vcpu->arch.mls_regs)) {
				if(i == instr->Rn_index)
					kvm_write_guest(vcpu->kvm, gpa, &origin_rn, 4);
				else
					kvm_write_guest(vcpu->kvm, gpa, &vcpu->arch.regs[i], 4);
				gpa = gpa + 4;
			}
		}
	} else {
		for (i = 8; i <= 12; i++) {
			if (test_bit(i, (void*)&vcpu->arch.mls_regs)) {
				kvm_write_guest(vcpu->kvm, gpa, &vcpu->arch.usr_regs[i-8], 4);
				gpa = gpa + 4;
			}
		}
	}

	if (test_bit(13, (void*)&vcpu->arch.mls_regs)) {
		banked_sp = load_banked_sp(vcpu, USR);
		kvm_write_guest(vcpu->kvm, gpa, &banked_sp, 4);
		gpa = gpa + 4;
	}
	if (test_bit(14, (void*)&vcpu->arch.mls_regs)) {
		banked_lr = load_banked_lr(vcpu, USR);
		kvm_write_guest(vcpu->kvm, gpa, &banked_lr, 4);
		gpa = gpa + 4;
	}
	if (test_bit(15, (void*)&vcpu->arch.mls_regs)) {
		if (instr->Rn_index == 15) KVM_BUG(2);

		tmp_pc = vcpu->arch.regs[15] + 4;
		kvm_write_guest(vcpu->kvm, gpa, &tmp_pc, 4);
		gpa = gpa + 4;
	}

	return EMULATE_DONE;
}

/**
  * @brief kvmarm_handle_load uses for handling "Load" related instruction
  *
  * "Load" instructions are catagoried as many types in ISA of ARM architecture, 
  * such as LDR, LDRB, LDRBT, LDRT and so on. Its behavior are mostly the same.
  * The most important difference is that their data type are different.
  * In emulation part, we use the same function to emulate different type of "Load" instructions.
  * Its behavior will be changed by parameter "bytes" which means the data type of this instruction.
  * We will emulate these instruction by getting the Guest Physical Address from Memory virtualization.
  *
  * @param *run  Main data about KVM (ARMvisor)
  * @param *vcpu Virtual CPU
  * @param rd    Register Rd
  * @param bytes The data type of this instruction 
  */
static int kvmarm_handle_load(struct kvm_run *run, struct kvm_vcpu *vcpu, unsigned int rd, unsigned int bytes)
{
	run->mmio.phys_addr = vcpu->arch.paddr_accessed;
	run->mmio.len = bytes;
	run->mmio.is_write = 0;

	vcpu->arch.io_gpr = rd;
	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = 0;
	vcpu->arch.is_mls = 0;
	return EMULATE_DO_MMIO;
}

/**
  * @brief kvmarm_handle_store uses for handling "Store" related instruction
  *
  * "Store" instructions are catagoried as many types in ISA of ARM architecture, 
  * such as STR, STRB, STRBT, STRT and so on. Its behavior are mostly the same.
  * The most important difference is that their data type are different.
  * In emulation part, we use the same function to emulate different type of "Store" instructions.
  * Its behavior will be changed by parameter "bytes" which means the data type of this instruction.
  * We will emulate these instruction by getting the Guest Physical Address from Memory virtualization.
  *
  * @param *run  Main data about KVM (ARMvisor)
  * @param *vcpu Virtual CPU
  * @param val
  * @param bytes The data type of this instruction 
  */
static int kvmarm_handle_store(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 val, unsigned int bytes)
{
	u8 *data = run->mmio.data;

	run->mmio.phys_addr = vcpu->arch.paddr_accessed;
	run->mmio.len = bytes;
	run->mmio.is_write = 1;
	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = 1;
	vcpu->arch.is_mls = 0;

	switch (bytes) {
	case 1: 
		*(u8 *)data = val;
		break;
	case 2: 
		*(u16 *)data = val; 
		break;
	case 4: 
		*(u32 *)data = val;
		break;
	default: 
		KVM_BUG(1);
	}
	return EMULATE_DO_MMIO;
}

u32 kvmarm_handle_guest_store(struct instruction *instr, u32 inst, struct kvm_vcpu *vcpu,u32 bytes)
{
	u32 gva, gpa;
	u32 value;

	vcpu->arch.signed_flag = 0;

	gva = get_address(instr, inst, vcpu);

	gpa = vcpu->arch.mmu.gva_to_gpa(vcpu, gva);

	if (instr->Rd_index == 15) {
		value = vcpu->arch.regs[instr->Rd_index] + 4;
	} else {
		value = vcpu->arch.regs[instr->Rd_index];
	}
	kvm_write_guest(vcpu->kvm, gpa, &value, bytes);

	return EMULATE_DONE;
}

u32 kvmarm_handle_guest_load(struct instruction *instr, u32 inst, struct kvm_vcpu *vcpu, u32 bytes)
{
	u32 gva, gpa;
	u32 value;

	gva = get_address(instr, inst, vcpu);
	gpa = vcpu->arch.mmu.gva_to_gpa(vcpu, gva);

	kvm_read_guest(vcpu->kvm, gpa, &value, bytes);
	if (bytes == 1) value = value & 0x000000ff;
	vcpu->arch.regs[instr->Rd_index] = value;

	return EMULATE_DONE;
}

u32 kvmarm_handle_guest_store_ex(struct instruction *instr, struct kvm_vcpu *vcpu)
{
	u32 gva = vcpu->arch.regs[instr->Rn_index];
	u32 gpa = vcpu->arch.mmu.gva_to_gpa(vcpu, gva);
	u32 value = vcpu->arch.regs[instr->imme];

	kvm_write_guest(vcpu->kvm, gpa, &value, 4);

	//TODO : SMP Problem
	//assume : always store ok
	vcpu->arch.regs[instr->Rd_index] = 0;
	return EMULATE_DONE;
}

/**
  * @brief Emulate Load/Store inst: ldr,ldrb.ldrbt.ldrt.str.strb,strbt,strt 
  *
  * Emulate "ldr,ldrb.ldrbt.ldrt.str.strb,strbt,strt"; Default: Update the LS Word/Byte base register
  */
int emu_ls1(struct instruction *instr, u32 inst, struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	int r;
	kvm_profiling_count(&vcpu->stat.ls_inst);

	vcpu->arch.signed_flag = 0;
	switch (instr->opcode2) {
	case OP2_LDR_1:
		r = kvmarm_handle_load(run, vcpu, instr->Rd_index, 4);
		break;
	case OP2_STRB_1:
		if(vcpu->arch.is_mmio_inst == 1)
			r = kvmarm_handle_store(run, vcpu, vcpu->arch.regs[instr->Rd_index], 1);
		else
			r = kvmarm_handle_guest_store(instr, inst, vcpu, 1);
		break;
	case OP2_LDRB_1:
		KVM_BUG(1);
		r = kvmarm_handle_load(run, vcpu, instr->Rd_index, 1);
		break;
	case OP2_STR_1:
		if (vcpu->arch.is_mmio_inst == 1)
			r = kvmarm_handle_store(run, vcpu, vcpu->arch.regs[instr->Rd_index], 4);
		else
			r = kvmarm_handle_guest_store(instr, inst, vcpu, 4);
		break;
	case OP2_LDRB_2:
		r = kvmarm_handle_load(run, vcpu, instr->Rd_index, 1);
		break;
	case OP2_STRB_2:
		r = kvmarm_handle_store(run, vcpu, vcpu->arch.regs[instr->Rd_index], 1);
		break;
	case OP2_STR_2:
		if(vcpu->arch.is_mmio_inst == 1)
			r = kvmarm_handle_store(run, vcpu, vcpu->arch.regs[instr->Rd_index], 4);
		else
			r = kvmarm_handle_guest_store(instr, inst, vcpu, 4);
		break;
	case OP2_LDR_2:
		r = kvmarm_handle_load(run, vcpu, instr->Rd_index, 4);
		break;
	case OP2_STR_3:
		KVM_BUG(1);
		r = kvmarm_handle_store(run, vcpu, vcpu->arch.regs[instr->Rd_index], 4);
		break;
	case OP2_LDRB_3:
		KVM_BUG(1);
		r = kvmarm_handle_load(run, vcpu, instr->Rd_index, 1);
		break;
	case OP2_LDR_3:
		KVM_BUG(1);
		r = kvmarm_handle_load(run, vcpu, instr->Rd_index, 4);
		break;
	case OP2_STRB_3:
		KVM_BUG(1);
		r = kvmarm_handle_store(run, vcpu, vcpu->arch.regs[instr->Rd_index], 1);
		break;
	case OP2_STRT:
		if (instr->Rn_index == 13 || instr->Rn_index == 14) KVM_BUG(2);
		r = kvmarm_handle_guest_store(instr, inst, vcpu, 4);
		break;
	case OP2_LDRT:
		if (instr->Rn_index == 13 || instr->Rn_index == 14) KVM_BUG(2);
		r = kvmarm_handle_guest_load(instr, inst, vcpu, 4);
		break;
	case OP2_STRBT:
		if (instr->Rn_index == 13 || instr->Rn_index == 14) KVM_BUG(2);
		r = kvmarm_handle_guest_store(instr, inst, vcpu, 1);
		break;
	case OP2_LDRBT:
		if (instr->Rn_index == 13 || instr->Rn_index == 14) KVM_BUG(2);
		r = kvmarm_handle_guest_load(instr, inst, vcpu, 1);
		break;
	default:
		printk("error occur on decode\n");
		BUG();
		r = EMULATE_FAIL;
	}
	//update ! address
	if (vcpu->arch.is_mmio_inst == 1) 
		get_address(instr, inst, vcpu);

	return r;
}

/**
  * @brief emulate LOAD/STORE inst.: LDREX
  */
int emu_ls_ldrex(struct instruction *instr, struct kvm_vcpu *vcpu, u32 inst)
{
	kvm_profiling_count(&vcpu->stat.ls_inst);

	KVM_BUG(3);
	if (vcpu->arch.is_mmio_inst == 1)
		LS_sh_update_base_addr(inst, vcpu);

	return -1;
}

/**
  * @brief emulate LOAD/STORE inst.: STREX
  */
int emu_ls_strex(struct instruction *instr, struct kvm_vcpu *vcpu, u32 inst)
{
	int r;
	kvm_profiling_count(&vcpu->stat.ls_inst);

	vcpu->arch.is_mmio_inst = 0;
	r = kvmarm_handle_guest_store_ex(instr, vcpu);

	if (vcpu->arch.is_mmio_inst == 1)
		LS_sh_update_base_addr(inst, vcpu);

	return r;
}

/**
  * @brief emulate LOAD/STORE inst.: LDRH
  */
int emu_ls_ldrh(struct instruction *instr, struct kvm_run *run, struct kvm_vcpu *vcpu, u32 inst)
{
	int r;
	kvm_profiling_count(&vcpu->stat.ls_inst);

	r = kvmarm_handle_load(run, vcpu, instr->Rd_index, 2);

	if (vcpu->arch.is_mmio_inst == 1)
		LS_sh_update_base_addr(inst, vcpu);

	return r;
}

/**
  * @brief emulate LOAD/STORE inst.: STRH
  */
int emu_ls_strh(struct instruction *instr, struct kvm_run *run, struct kvm_vcpu *vcpu, u32 inst)
{
	int r;
	kvm_profiling_count(&vcpu->stat.ls_inst);

	r = kvmarm_handle_store(run, vcpu, vcpu->arch.regs[instr->Rd_index], 2);

	if (vcpu->arch.is_mmio_inst == 1)
		LS_sh_update_base_addr(inst, vcpu);

	return r;
}

/**
  * @brief emulate LOAD/STORE inst.: STRD
  */
int emu_ls_strd(struct instruction *instr, struct kvm_vcpu *vcpu, u32 inst)
{
	kvm_profiling_count(&vcpu->stat.ls_inst);

	BUG();

	if (vcpu->arch.is_mmio_inst == 1)
		LS_sh_update_base_addr(inst, vcpu);

	return -1;
}

/**
  * @brief emulate LOAD/STORE inst.: LDRSH
  */
int emu_ls_ldrsh(struct instruction *instr, struct kvm_run *run, struct kvm_vcpu *vcpu, u32 inst)
{
	int r;
	kvm_profiling_count(&vcpu->stat.ls_inst);

	if (vcpu->arch.is_mmio_inst == 1) {	
		vcpu->arch.signed_flag = 1;
		r = kvmarm_handle_load(run, vcpu, instr->Rd_index, 2);
	} else {
		KVM_BUG(5);
	}

	if (vcpu->arch.is_mmio_inst == 1)
		LS_sh_update_base_addr(inst, vcpu);

	return r;
}

/**
  * @brief emulate LOAD/STORE inst.: LDRSB
  */
int emu_ls_ldrsb(struct instruction *instr, struct kvm_run *run, struct kvm_vcpu *vcpu, u32 inst)
{
	int r;
	kvm_profiling_count(&vcpu->stat.ls_inst);

	KVM_BUG(4);
	r = kvmarm_handle_load(run, vcpu, instr->Rd_index, 1);
	vcpu->arch.signed_flag = 1;

	if (vcpu->arch.is_mmio_inst == 1)
		LS_sh_update_base_addr(inst, vcpu);

	return r;
}

/**
  * @brief Emulate Multimedia Load/Store instructions
  *
  * We assume that there is no MMIO happened here.
  * In the beginning of this function, we have to change to MLS addressing mode and update the address.
  */
int emu_mls(struct kvm_run *run, struct kvm_vcpu *vcpu, struct instruction *instr, u32 inst)
{
	u32 start_address, end_address;
	u32 origin_rn = multi_address(instr, &start_address, &end_address, inst, vcpu);

	int r;

	kvm_profiling_count(&vcpu->stat.mls_inst);
	kvm_profiling_pc(&vcpu->stat.mls_info, vcpu->arch.regs[15]);

	switch (instr->opcode2) {
	case OP2_STM1_1:
		if (vcpu->arch.is_mmio_inst == 1) {
			r = kvmarm_handle_mul_store(run, vcpu, instr, start_address, end_address, 1, origin_rn);
		} else {
			r = kvmarm_handle_guest_stm(instr, vcpu, start_address, origin_rn);
		}
		break;
	case OP2_STM1_2:
		if(vcpu->arch.is_mmio_inst == 1) {
			r = kvmarm_handle_mul_store(run, vcpu, instr, start_address, end_address, 1, origin_rn);
		} else {
			r = kvmarm_handle_guest_stm(instr, vcpu, start_address, origin_rn);
			KVM_BUG(1);
		}
		break;
	case OP2_LDM1_1:
		r = kvmarm_handle_mul_load(run, vcpu, start_address, end_address, 1);
		break;
	case OP2_LDM1_2:
		r = kvmarm_handle_mul_load(run, vcpu, start_address, end_address, 1);
		break;
	case OP2_STM1_3:
		if (vcpu->arch.is_mmio_inst == 1) {
			r = kvmarm_handle_mul_store(run, vcpu, instr, start_address, end_address, 1, origin_rn);
		} else {
			r = kvmarm_handle_guest_stm(instr, vcpu, start_address, origin_rn);
		}
		break;
	case OP2_STM1_4:
		if (vcpu->arch.is_mmio_inst == 1) {
			r =kvmarm_handle_mul_store(run, vcpu, instr, start_address, end_address, 1, origin_rn);
		} else {
			KVM_BUG(1);
			r = kvmarm_handle_guest_stm(instr, vcpu, start_address, origin_rn);
		}
		break;
	case OP2_LDM1_3:
		r = kvmarm_handle_mul_load(run, vcpu, start_address, end_address, 1);
		break;
	case OP2_STM2_1:
		if (vcpu->arch.is_mmio_inst == 1) {
			KVM_BUG(4);
		} else {
			r = kvmarm_handle_guest_stm2(instr, vcpu, start_address, origin_rn);
		}
		break;
	case OP2_STM2_2:
		if (vcpu->arch.is_mmio_inst == 1)
			KVM_BUG(4);
		else
			r = kvmarm_handle_guest_stm2(instr, vcpu, start_address, origin_rn);
		KVM_BUG(6);
		break;
	case OP2_LDM2_1:
		if (vcpu->arch.is_mmio_inst == 1) {
			KVM_BUG(5);
		} else {
			r = kvmarm_handle_guest_ldm2(vcpu, start_address);
		}
		break;
	case OP2_LDM3_1:
		if (vcpu->arch.is_mmio_inst == 1) {
			KVM_BUG(3);
		} else {
			r = kvmarm_handle_guest_ldm3(vcpu, start_address);
		}
		break;
	case OP2_LDM3_2:
		if (vcpu->arch.is_mmio_inst == 1)
			KVM_BUG(3);
		else
			r = kvmarm_handle_guest_ldm3(vcpu, start_address);
		KVM_BUG(6);
		break;

	default:
		KVM_BUG(7);
		return EMULATE_FAIL;
	}
	return r;
}

void change_processor_state(u32 inst, struct kvm_vcpu *vcpu, u32 tmp_cpsr)
{
	u32 imod = TRANSFER_BITSEG(18, 19, inst);
	u32 mmod = test_bit(17, (void*)&inst);
	u32 mode = TRANSFER_BITSEG(0, 4, inst);

	if (test_bit(1, (void*)&imod) == 1) {
		if (test_bit(8, (void*)&inst) == 1)
			tmp_cpsr = (tmp_cpsr & ~PSR_A_BIT) | (test_bit(0, (void*)&imod) << 8);
		if (test_bit(7, (void*)&inst) == 1)
			tmp_cpsr = (tmp_cpsr & ~PSR_I_BIT) | (test_bit(0, (void*)&imod) << 7);
		if (test_bit(6, (void*)&inst) == 1)
			tmp_cpsr = (tmp_cpsr & ~PSR_F_BIT) | (test_bit(0, (void*)&imod) << 6);
	}
	if (mmod == 1) {
		tmp_cpsr = (tmp_cpsr & ~MODE_MASK) | mode;
	}
	modify_cpsr(vcpu, tmp_cpsr);
} 

int emu_cps(u32 inst, struct kvm_vcpu *vcpu)
{
	u32 tmp_cpsr = vcpu->arch.virtual_cpsr;

	kvm_profiling_count(&vcpu->stat.cps_inst);
	kvm_profiling_pc(&vcpu->stat.cps_info, vcpu->arch.regs[15]);

	if ((tmp_cpsr & MODE_MASK) != USR_MODE) {
		change_processor_state(inst, vcpu, tmp_cpsr);
	} else {
		KVM_BUG(1);	
	}

	return EMULATE_DONE;	
}

// to be fixed
// not yet care where the context is in the user space or not
// in the future it must  be fixed
static u32 check_field_mask(u32 inst)
{
	u32 byte_mask = 0x0;

	if (test_bit(FIELD_MASK_0, (void*)&inst)) {
		byte_mask |= 0x000000FF;
	}
	
	if (test_bit(FIELD_MASK_1, (void*)&inst)) {
		byte_mask |= 0x0000FF00;
	}
	if (test_bit(FIELD_MASK_2, (void*)&inst)) {
		byte_mask |= 0x00FF0000;
	}
	if (test_bit(FIELD_MASK_3, (void*)&inst)) {
		byte_mask |= 0xFF000000;
	}	
	
	return byte_mask;
	
}

/**
  * @brief emulate the instruction which uses "msr" to write CPSR
  */
int emu_msr_cpsr(u32 inst,struct kvm_vcpu *vcpu, u32 operand)
{
	u32 mask = 0;
	u32 tmp_cpsr;
	u32 byte_mask = 0x0;
	u32 userMask = 0xF80F0200;
	u32 privMask = 0x000001DF;
	u32 stateMask = 0x01000020;

	kvm_profiling_count(&vcpu->stat.msr_inst);
	kvm_profiling_pc(&vcpu->stat.msr_info, vcpu->arch.regs[15]);

	tmp_cpsr = vcpu->arch.virtual_cpsr;
	byte_mask = check_field_mask(inst);

	if ((tmp_cpsr & MODE_MASK) == FIELD_NOT_PRIVILIGED) {
		KVM_BUG(2);
		mask = byte_mask & userMask;
	} else {
		if (operand & stateMask)
			printk("operand set error:%ld\n",(unsigned long)operand);
		else 
			mask = byte_mask & (userMask | privMask);
	}
	tmp_cpsr = (tmp_cpsr & ~(mask)) | (operand & mask);

	modify_cpsr(vcpu, tmp_cpsr);
	return EMULATE_DONE; 
}

/**
  * @brief emulate instructions which use "msr" to write SPSR
  */
int emu_msr_spsr(u32 inst,struct kvm_vcpu *vcpu, u32 operand)
{
	u32 spsr = 0;
	u32 mask = 0;
	u32 byte_mask = 0x0;
	u32 userMask = 0xF80F0200;
	u32 privMask = 0x000001DF;
	u32 stateMask = 0x01000020;
	u32 mode = TRANSFER_MODEBITS(vcpu->arch.virtual_cpsr & MODE_MASK);

	kvm_profiling_count(&vcpu->stat.msr_inst);
	kvm_profiling_pc(&vcpu->stat.msr_info, vcpu->arch.regs[15]);

	spsr = load_banked_spsr(vcpu, mode);

	byte_mask = check_field_mask(inst);
	
	mask = byte_mask & (userMask | privMask | stateMask);	  
	spsr = (spsr & ~(mask)) | (operand & mask);
	store_banked_spsr(vcpu, mode, spsr);
	return EMULATE_DONE; 
}

/**
  * @brief emulate the instruction which use "mrs" to write SPSR
  */
int emu_mrs_spsr(struct instruction *instr, struct kvm_vcpu *vcpu)
{
	u32 mode = TRANSFER_MODEBITS(vcpu->arch.virtual_cpsr & MODE_MASK);
	
	kvm_profiling_count(&vcpu->stat.mrs_inst);
	kvm_profiling_pc(&vcpu->stat.mrs_info, vcpu->arch.regs[15]);

	vcpu->arch.regs[instr->Rd_index] = load_banked_spsr(vcpu, mode);
	return EMULATE_DONE;
}

/**
  * @brief emulate the instruction which use "mrs" to write CPSR
  */
int emu_mrs_cpsr(struct instruction *instr, struct kvm_vcpu *vcpu)
{
	kvm_profiling_count(&vcpu->stat.mrs_inst);
	kvm_profiling_pc(&vcpu->stat.mrs_info, vcpu->arch.regs[15]);

	vcpu->arch.regs[instr->Rd_index] = vcpu->arch.virtual_cpsr;
	return EMULATE_DONE;
}

/**
  * @brief emulate the instructions which use "mov" to access data
  */
int emu_data(struct instruction *instr, struct kvm_vcpu *vcpu)
{
	u32 rn_data = vcpu->arch.regs[instr->Rn_index];
	u32 value;
	u32 spsr_data;
	u32 mode = TRANSFER_MODEBITS(vcpu->arch.virtual_cpsr & MODE_MASK);

	kvm_profiling_count(&vcpu->stat.data_inst);
	kvm_profiling_pc(&vcpu->stat.data_info, vcpu->arch.regs[15]);


	if (instr->opcode2 != 13)
		printk("[kvm] Data_inst : %d, pc=%x \n", instr->opcode2, vcpu->arch.regs[15]);

	switch (instr->opcode2) {
	case OP2_AND:
		KVM_BUG(1);
		value = rn_data & instr->imme;
		break;
	case OP2_EOR:
		KVM_BUG(1);
		value = rn_data ^ instr->imme;
		break;
	case OP2_SUB:
		KVM_BUG(1);
		value = rn_data - instr->imme;
		break;
	case OP2_RSB:
		KVM_BUG(1);
		value = instr->imme - rn_data;
		break;
	case OP2_ADD:
		KVM_BUG(1);
		value = rn_data + instr->imme;
		break;
	case OP2_ADC:
		KVM_BUG(1);
		value = rn_data + instr->imme + test_bit(29, (void*)&vcpu->arch.virtual_cpsr);
		break;
	case OP2_SBC:
		KVM_BUG(1);
		value = rn_data - instr->imme - (1 -test_bit(29, (void*)&vcpu->arch.virtual_cpsr));
		break;
	case OP2_RSC:
		KVM_BUG(1);
		value = instr->imme - rn_data + test_bit(20, (void*)&vcpu->arch.virtual_cpsr) - 1;
		break;
	case OP2_ORR:
		KVM_BUG(1);
		value = rn_data | instr->imme;
		break;
	case OP2_MOV:
		value = instr->imme;
		break;
	case OP2_BIC:
		KVM_BUG(1);
		value = rn_data & (~instr->imme);
		break;
	case OP2_MVN:
		KVM_BUG(1);
		value = ~instr->imme;
		break;
	default:
		printk("NO support Data processing inst\n");
		KVM_BUG(2);
	}

	vcpu->arch.regs[instr->Rd_index] = value;
	
	if (instr->s_data && instr->Rd_index == 15) {
		spsr_data = load_banked_spsr(vcpu, mode);
		modify_cpsr(vcpu, spsr_data);
	} else {
		KVM_BUG(3);
	}
	return EMULATE_DONE;
}

static void emu_mcr_cp15_c1(struct instruction *instr, struct kvm_vcpu *vcpu)
{
	u32 value = vcpu->arch.regs[instr->Rd_index];
	struct mmu_test mmu;

	if (instr->opcode2 == 0) {
		mmu.pre_mmu_on = TRANSFER_BITSEG(0, 0, vcpu->arch.cp15.c1_sys);
		mmu.cur_mmu_on = TRANSFER_BITSEG(0, 0, value);
		vcpu->arch.cp15.c1_sys = value;
		if (mmu.pre_mmu_on != mmu.cur_mmu_on) {
			c15_reset_mmu(vcpu);
		}
	} else if (instr->opcode2 == 2) {
		vcpu->arch.cp15.c1_coproc = value;
	}
	
	switch (instr->imme) {
	case MCR_CP15_C1_C0:
		switch (instr->opcode2) {
		case OP2_CTRL_BT_TRAP:
			BT(NOP);
			break;
		case OP2_AUX_CTRL:
			break;
		case OP2_COPROC_ACCESS_CTRL:
			break;
		default:
			kvmarm_return_undefine();
			break;
		}
		break;
	case MCR_CP15_C1_C1:
		switch (instr->opcode2) {
		case OP2_SECURE_CONF: 
			break;
		case OP2_SECURE_DEBUG_ENABLE:
			break;
		case OP2_NONSECURE_ACCESS_CTRL:
			break;
		default:
			kvmarm_return_undefine();
			break;
		}
		break;
	default:
		kvmarm_return_undefine();
		break;
	}

}

static void emu_mcr_cp15_c2(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	struct mmu_test mmu;

	mmu.pre_mmu_on = TRANSFER_BITSEG(0,0,vcpu->arch.cp15.c1_sys);
	if (instr->opcode2 == 0) {
		vcpu->arch.cp15.c2_base0 = value;
		c15_reset_ttbr0(vcpu);
	} else if (instr->opcode2 == 1) {
		vcpu->arch.cp15.c2_base1 = value;
		printk("!!--> [kvm] pc:%x, change TTBR1 to:%x\n", vcpu->arch.regs[15],value);
	} else if (instr->opcode2 == 2) {
		vcpu->arch.cp15.c2_control = value;
		printk("!!--> [kvm] pc:%x, change TTBRC to:%x\n", vcpu->arch.regs[15],value);
	}
}

static void emu_mcr_cp15_c7_c5(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	switch (instr->opcode2) {
	case OP2_INVALID_ENTIRE_I_CACHE: 
		__asm__ __volatile__(
					"mcr p15, #0, %0, c7, c5, #0"
					:
					:"r"(value)
					);
		kvmarm_fast_trap_bt(vcpu, instr);
		break;
	case OP2_INVALID_I_CACHE_LINE_MVA: 
		__asm__ __volatile__(
					"mcr p15, #0, %0, c7, c5, #1"
					:
					:"r"(value)
					);
		kvmarm_fast_trap_bt(vcpu, instr);
		break;
	case OP2_INVALID_I_CACHE_LINE_SETWAY: 
		__asm__ __volatile__(
					"mcr p15, #0, %0, c7, c5, #2"
					:
					:"r"(value)
					);
		kvmarm_fast_trap_bt(vcpu, instr);
		break;
	case OP2_FLUSH_PREFETCH_BUFFER:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c7, c5, #4"
					:
					:"r"(value)
					);
		kvmarm_fast_trap_bt(vcpu, instr);
		break;
	case OP2_FLUSH_ENTIRE_BRANCH_TARGET_CACHE: 
		__asm__ __volatile__(
					"mcr p15, #0, %0, c7, c5, #6"
					:
					:"r"(value)
					);
		BT(NOP);
		break;
	case OP2_FLUSH_BRANCH_TARGET_ENTRY: 
		__asm__ __volatile__(
					"mcr p15, #0, %0, c7, c5, #7"
					:
					:"r"(value)
					);
		kvmarm_fast_trap_bt(vcpu, instr);
		break;
	default:
		BUG();
	}
}

static void emu_mcr_cp15_c7_c6(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	switch (instr->opcode2) {
	case OP2_INVALID_ENTIRE_D_CACHE: 
		flush_cache_all();
		break;
	case OP2_INVALID_D_CACHE_LINE_MVA:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c7, c6, #1"
					:
					:"r"(value)
					);
		kvmarm_fast_trap_bt(vcpu, instr);
		break;
	case OP2_INVALID_D_CACHE_LINE_SETWAY:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c7, c6, #2"
					:
					:"r"(value)
					);
		kvmarm_fast_trap_bt(vcpu, instr);
		break;
	default:
			BUG();
	}
}

static void emu_mcr_cp15_c7_c7(struct instruction *instr)
{
	switch (instr->opcode2) {
	case OP2_INVALID_ID_CACHE_FLUSH_BRANCH_ENTRY:
		flush_cache_all();
		break;
	default:
		BUG();
	}
}

static void emu_mcr_cp15_c7_c10(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	switch (instr->opcode2) {
	case OP2_CLEAN_ENTIRE_D_CACHE:
		flush_cache_all();
		break;
	case OP2_CLEAN_D_CACHE_LINE_MVA:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c7, c10, #1"
					:
					:"r"(value)
					);
		kvmarm_fast_trap_bt(vcpu, instr);
		break;
	case OP2_CLEAN_D_CACHE_LINE_SETWAY:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c7, c10, #2"
					:
					:"r"(value)
					);
		kvmarm_fast_trap_bt(vcpu, instr);
		break;
	default:
		BUG();
	}
}

static void emu_mcr_cp15_c7_c11(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	if (instr->opcode2 == 0)
		__asm__ __volatile__(
				"mcr p15, #0, %0, c7, c11, #0"
				:
				:"r"(value)
				);
	else if (instr->opcode2 == 1)
		__asm__ __volatile__(
				"mcr p15, #0, %0, c7, c11, #1"
				:
				:"r"(value)
				);
	else if (instr->opcode2 == 2)
		__asm__ __volatile__(
				"mcr p15, #0, %0, c7, c11, #2"
				:
				:"r"(value)
				);
}

static void emu_mcr_cp15_c7_c13(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	if( instr->opcode2 == 1 )
		__asm__ __volatile__(
				"mcr p15, #0, %0, c7, c13, #1"
				:
				:"r"(value)
				);
}

static void emu_mcr_cp15_c7_c14(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	switch (instr->opcode2) {
	case OP2_CLEAN_INVALID_ENTIRE_D_CACHE:
		flush_cache_all();
		break;
	case OP2_CLEAN_INVALID_D_CACHE_LINE_MVA:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c7, c14, #1"
					:
					:"r"(value)
					);
		vcpu->arch.trapped_inst = NOP;
		kvmarm_fast_trap_bt(vcpu, instr);
		break;
	case OP2_CLEAN_INVALID_D_CACHE_LINE_SETWAY:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c7, c14, #2"
					:
					:"r"(value)
					);
		kvmarm_fast_trap_bt(vcpu, instr);
		break;
	default:
		BUG();
	}
}

static void emu_mcr_cp15_c7_c15(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	if( instr->opcode2 == 0 )
		printk("XX mcr cp15, c7, c15, 0 \n");
	else if( instr->opcode2 == 1 )
		__asm__ __volatile__(
				"mcr p15, #0, %0, c7, c15, #1"
				:
				:"r"(value)
				);
	else if( instr->opcode2 == 2 )
		__asm__ __volatile__(
				"mcr p15, #0, %0, c7, c15, #2"
				:
				:"r"(value)
				);
}

static void emu_mcr_cp15_c7(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	kvm_profiling_count(&vcpu->stat.cache_inst);
	switch (instr->imme) {
	case MCR_CP15_C7_C0:
		if (instr->opcode2 == OP2_MCR_WAIT_INTERRUPT) { 
			//TODO
			//wait_for_interrupt();
			break;
		}
		break;
	case MCR_CP15_C7_C5:
		emu_mcr_cp15_c7_c5(instr, vcpu, value);
		break;
	case MCR_CP15_C7_C6:
		emu_mcr_cp15_c7_c6(instr, vcpu, value);
		break;
	case MCR_CP15_C7_C7:
		emu_mcr_cp15_c7_c7(instr);
		break;
	case MCR_CP15_C7_C10:
		emu_mcr_cp15_c7_c10(instr, vcpu, value);
		break;
	case MCR_CP15_C7_C11:
		emu_mcr_cp15_c7_c11(instr, vcpu, value);
		break;
	case MCR_CP15_C7_C13:
		emu_mcr_cp15_c7_c13(instr, vcpu, value);
		break;
	case MCR_CP15_C7_C14:
		emu_mcr_cp15_c7_c14(instr, vcpu, value);
		break;
	case MCR_CP15_C7_C15:
		emu_mcr_cp15_c7_c15(instr, vcpu, value);
		break;
	default:
		BUG();
	}
}

static void emu_mcr_cp15_c8_c5(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	switch (instr->opcode2) {
	case OP2_INVALID_I_TLB_UNLOCKED_ENTRY: 
		__asm__ __volatile__(
					"mcr p15, #0, %0, c8, c5, #0"
					:
					:"r"(value)
					);
		BT(NOP);
		break;
	case OP2_INVALID_I_TLB_ENTRY_MVA:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c8, c5, #1"
					:
					:"r"(value)
					);
		BT(NOP);
		break;
	case OP2_INVALID_I_TLB_ENTRY_ASID_MATCH: 
		__asm__ __volatile__(
					"mcr p15, #0, %0, c8, c5, #2"
					:
					:"r"(value)
					);
		BT(NOP);
		break;
	case OP2_INVALID_I_TLB_SINGLE_ENTRY_MVA:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c8, c5, #3"
					:
					:"r"(value)
					);
		kvmarm_return_undefine();
		break;
	default:
		kvmarm_return_undefine();
		break;
	}
}

static void emu_mcr_cp15_c8_c6(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	switch (instr->opcode2) {
	case OP2_INVALID_D_TLB_UNLOCKED_ENTRY:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c8, c6, #0"
					:
					:"r"(value)
					);
		BT(NOP);
		break;
	case OP2_INVALID_D_TLB_ENTRY_MVA:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c8, c6, #1"
					:
					:"r"(value)
					);
		BT(NOP);
		break;
	case OP2_INVALID_D_TLB_ENTRY_ASID_MATCH:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c8, c6, #2"
					:
					:"r"(value)
					);
		BT(NOP);
		break;
	case OP2_INVALID_D_TLB_SINGLE_ENTRY_MVA:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c8, c6, #3"
					:
					:"r"(value)
					);
		kvmarm_return_undefine();
		break;
	default:
		kvmarm_return_undefine();
		break;
	}
}

static void emu_mcr_cp15_c8_c7(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	switch (instr->opcode2) {
	case OP2_INVALID_UTLB_UNLOCKED_ENTRY: 
		BT(NOP);
		break;
	case OP2_INVALID_UTLB_ENTRY_MVA:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c8, c7, #1"
					:
					:"r"(value)
					);
		BT(NOP);
		break;
	case OP2_INVALID_UTLB_ASID_MATCH:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c8, c7, #2"
					:
					:"r"(value)
					);
		BT(NOP);
		break;
	case OP2_INVALID_UTLB_SINGLE_ENTRY_MVA:
		__asm__ __volatile__(
					"mcr p15, #0, %0, c8, c7, #3"
					:
					:"r"(value)
					);
		kvmarm_return_undefine();
		break;
	default:
		kvmarm_return_undefine();
		break;
	}
}

//TLB operation native run
static void emu_mcr_cp15_c8(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	kvm_profiling_count(&vcpu->stat.tlb_inst);
	switch (instr->imme) {
	case MCR_CP15_C8_C5:
		emu_mcr_cp15_c8_c5(instr, vcpu, value);
		break;
	case MCR_CP15_C8_C6:
		emu_mcr_cp15_c8_c6(instr, vcpu, value);
		break;
	case MCR_CP15_C8_C7:
		emu_mcr_cp15_c8_c7(instr, vcpu, value);
		break;
	default:
		kvmarm_return_undefine();
		break;
	}
}

static void emu_mcr_cp15_c9(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	vcpu->arch.cp15.c9_data = value;
	__asm__ __volatile__(
			"mcr p15, #0, %0, c9, c0, #0"
			:
			:"r"(value)
			);
}

static void emu_mcr_cp15_c13(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	if (instr->opcode2 == 0) {
		vcpu->arch.cp15.c13_fcse = value;
		__asm__ __volatile__(
				"mcr p15, #0, %0, c13, c0, #0"
				:
				:"r"(value)
				);
	} else if (instr->opcode2 == 1) {
		vcpu->arch.cp15.c13_context = value;
		vcpu->arch.ctxt_id = value;		
	} else if (instr->opcode2 == 2) {
		vcpu->arch.cp15.c13_tls1 = value;
		__asm__ __volatile__(
				"mcr p15, #0, %0, c13, c0, #2"
				:
				:"r"(value)
				);
	} else if (instr->opcode2 == 3) {
		vcpu->arch.cp15.c13_tls2 = value;
		__asm__ __volatile__(
				"mcr p15, #0, %0, c13, c0, #3"
				:
				:"r"(value)
				);
	} else if (instr->opcode2 == 4) {
		vcpu->arch.cp15.c13_tls3 = value;
		__asm__ __volatile__(
				"mcr p15, #0, %0, c13, c0, #4"
				:
				:"r"(value)
				);
	}

	switch (instr->imme) {
	case 0:
		switch (instr->opcode2) {
		case OP2_CONTEXT_ID:
			BT(NOP);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
}

static void emu_mcr_cp15_c15(struct instruction *instr, struct kvm_vcpu *vcpu, u32 value)
{
	if (instr->imme == 1)
		__asm__ __volatile__(
				"mcr p15, #7, %0, c15, c1, #0"
				:
				:"r"(value)
				);
}

// MCR{<cond>} <coproc>, <opcode_1>, <Rd>, <CRn>, <CRm>{, <opcode_2>} 
int emu_mcr(struct instruction *instr, struct kvm_vcpu *vcpu)
{
	u32 value = vcpu->arch.regs[instr->Rd_index];
	
	kvm_profiling_count(&vcpu->stat.copr_inst);
	kvm_profiling_pc(&vcpu->stat.copr_info, vcpu->arch.regs[15]);

	switch (instr->Rn_index) {
	case MCR_CP15_C1: 
		emu_mcr_cp15_c1(instr, vcpu);
		break;
	case MCR_CP15_C2:
		emu_mcr_cp15_c2(instr, vcpu, value);
		break;
	case MCR_CP15_C3:
		vcpu->arch.cp15.c3 = value;
		c15_reset_domain(vcpu, value);
		break;
	case MCR_CP15_C5:
		if (instr->opcode2 == 0)
			vcpu->arch.cp15.c5_data = value;
		else if (instr->opcode2 == 1)
			vcpu->arch.cp15.c5_insn = value;
		break;
	case MCR_CP15_C6:
		if (instr->opcode2 == 0)
			vcpu->arch.cp15.c6_data = value;
		else if (instr->opcode2 == 2)
			vcpu->arch.cp15.c6_insn = value;
		break;
	case MCR_CP15_C7:
		emu_mcr_cp15_c7(instr, vcpu, value);
		break;
	case MCR_CP15_C8:
		emu_mcr_cp15_c8(instr, vcpu, value);
		break;
	case MCR_CP15_C9:
		emu_mcr_cp15_c9(instr, vcpu, value);
		break;
	case MCR_CP15_C13:
		emu_mcr_cp15_c13(instr, vcpu, value);
		break;	
	case MCR_CP15_C15:
		emu_mcr_cp15_c15(instr, vcpu, value);
		break;
	default:
		KVM_BUG(1);
		return EMULATE_FAIL;

	}
	return EMULATE_DONE;
}

int emu_mcrr(struct instruction *instr, struct kvm_vcpu *vcpu)
{
	u32 Rd,Rn;
	kvm_profiling_count(&vcpu->stat.copr_inst);
	kvm_profiling_pc(&vcpu->stat.copr_info, vcpu->arch.regs[15]);
	switch (instr->imme) {
	case 14:
		Rd = vcpu->arch.regs[instr->Rd_index];
		Rn = vcpu->arch.regs[instr->Rn_index]; 
		break;
	case 6: 
		Rd = vcpu->arch.regs[instr->Rd_index];
		Rn = vcpu->arch.regs[instr->Rn_index];
		break;
	}
	return EMULATE_DONE;
}

int emu_mrc(struct instruction *instr, struct kvm_vcpu *vcpu)
{

	u32 value = 0;
	kvm_profiling_count(&vcpu->stat.copr_inst);
	kvm_profiling_pc(&vcpu->stat.copr_info, vcpu->arch.regs[15]);
	switch (instr->Rn_index) {
	case 0:
		if (instr->opcode2 == 0) {
			value = vcpu->arch.cp15.c0_cpuid;
		} else if (instr->opcode2 == 1) {
			vcpu->arch.cp15.c0_cachetype = 0x1d192992;
			value = vcpu->arch.cp15.c0_cachetype;
		}
		break;
	case 1:
		if (instr->opcode2 == 0)
			value = vcpu->arch.cp15.c1_sys;
		else if (instr->opcode2 == 2)
			value = vcpu->arch.cp15.c1_coproc;
		break;
	case 2:
		if (instr->opcode2 == 0) {
			value = vcpu->arch.cp15.c2_base0;
		} else if (instr->opcode2 == 1) {
			KVM_BUG(1);
			value = vcpu->arch.cp15.c2_base1;
		} else if (instr->opcode2 == 2) {
			KVM_BUG(1);
			value = vcpu->arch.cp15.c2_control;
		}
		break;
	case 3:
		value = vcpu->arch.cp15.c3;
		break;
	case 5:
		if (instr->opcode2 == 0) {
			value = vcpu->arch.cp15.c5_data;
		} else if (instr->opcode2 == 1) {
			KVM_BUG(1);
			value = vcpu->arch.cp15.c5_insn;
		}
		break;
	case 6:
		if (instr->opcode2 == 0) {
			value = vcpu->arch.cp15.c6_data;
		} else if (instr->opcode2 == 1) {
			KVM_BUG(1);
			value = vcpu->arch.cp15.c6_insn;
			printk("[==========]vcpu->arch.cp15.c6_insn:%x\n",vcpu->arch.cp15.c6_insn);
		}
		break;


	case 9:
		if (instr->opcode2 == 0) {
			KVM_BUG(1);
			value = vcpu->arch.cp15.c9_data;
		}
		break;	
	case 13:
		KVM_BUG(1);
		if (instr->opcode2 == 0)
			value = vcpu->arch.cp15.c13_fcse;		
		else if (instr->opcode2 == 1)
			value = vcpu->arch.cp15.c13_context;
		else if (instr->opcode2 == 2)
			value = vcpu->arch.cp15.c13_tls1;
		else if (instr->opcode2 == 3)
			value = vcpu->arch.cp15.c13_tls2;
		else if (instr->opcode2 == 4)
			value = vcpu->arch.cp15.c13_tls3;
		break;

	default:
		printk("!!! CRn !!!\n");
		KVM_BUG(2);
		return EMULATE_FAIL;
	}

	vcpu->arch.regs[instr->Rd_index] = value;

	return EMULATE_DONE;
}
