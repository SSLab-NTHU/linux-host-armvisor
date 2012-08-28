/**
 *  @vsoft_vcpu.c
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

#include <linux/module.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_para.h>
#include <asm/cacheflush.h>
//#include "mmu.h"
#include "emulate_arm.h"
#include <vsoft_vcpu.h>

#define REG_PC 15

#define COND_EQ	0
#define COND_NE	1
#define COND_CS 2
#define COND_CC	3
#define COND_MI	4
#define COND_PL	5
#define COND_VS	6
#define COND_VC	7
#define COND_HI	8
#define COND_LS	9
#define COND_GE	10
#define COND_LT	11
#define COND_GT	12
#define COND_LE	13
#define COND_AL	14
#define COND_SPECIAL	15

#define OP_SETEND	0x10000
#define OP_RFE		0b10000001
#define OP_SRS		0b10000100

#define OP1_H_DATA_PROCESS	0b000
#define OP1_H_MSR_CPSR_DATA	0b001
#define OP1_H_LS_RBT_1		0b010
#define OP1_H_LS_RBT_2		0b011
#define OP1_H_MLS		0b100
#define OP1_H_COPROCESSOR	0b110
#define OP1_H_UNDEFINE		0b111

#define OP1_M_MRS_MSR_CPSR	0b0000
#define OP1_M_BKPT		0b0111
#define OP1_M_LS_REX_SWPB	0b1001
#define OP1_M_LS_RH		0b1011
#define OP1_M_LDRSB		0b1101
#define OP1_M_LS_RSH_RD		0b1111

#define OP1_MRS_W_CPSR	0x10
#define OP1_MRS_W_SPSR	0x14
#define OP1_MSR_W_CPSR	0x12
#define OP1_MSR_W_SPSR	0x16
#define OP1_BKPT	1110
#define OP1_SWP		0b10000
#define OP1_SWPB	0b10100
#define OP1_LDREX	0b11001
#define OP1_STREX	0b11000

#define OP1_NO_INST_1	0b10000
#define OP1_NO_INST_2	0b10100
#define OP1_MSR_CPSR	0b10010
#define OP1_MSR_SPSR	0b10110

#define OP1_SWI_1	0x01000000
#define OP1_SWI_2	0x01000010
#define OP1_SWI_3	0x01100000
#define OP1_SWI_4	0x01100010

#define OP1_CDP_1	0x00000000
#define OP1_CDP_2	0x00100000
#define OP1_MCR		0x00000010
#define OP1_MRC		0x00100010
#define OP1_MRRC 	0x05
#define OP1_MCRR 	0x04

#define OP_ALL_MCR 	0x0e000010
#define OP_ALL_MRC 	0x0e100010
#define OP_ALL_MCRR	0x0c400000
#define OP_ALL_MRRC 	0x0c500000

/**
  * @brief decode_opcode1 decode op1
  */
void decode_opcode1(struct instruction *instr, u32 input)
{
        instr->cond = input>>28 & 0xF; 
        instr->opcode = input>>20 & 0xFF;
}

/**
  * @brief decode_mcr decode "mcr", then call function to emulate "mcr"
  */
static void decode_mcr(struct instruction *instr, struct kvm_vcpu *vcpu)
{
	u32 inst = vcpu->arch.trapped_inst;
	u32 cp_num;

	cp_num = TRANSFER_BITSEG(8, 11, inst);
	if (cp_num == 15) {
		instr->Rn_index = TRANSFER_BITSEG(16, 19, inst);
		instr->Rd_index = TRANSFER_BITSEG(12, 15, inst);
		instr->imme = TRANSFER_BITSEG(0, 3, inst);
		instr->opcode2 = TRANSFER_BITSEG(5, 7, inst);
		instr->return_info = emu_mcr(instr, vcpu);
	} else {
		printk("MCR with cp %d, which is not emulated.\n", cp_num);
	}
}

/**
  * @brief decode_mrc decode "mrc", then call function to emulate "mrc"
  */
static void decode_mrc(struct instruction *instr, struct kvm_vcpu *vcpu)
{
	u32 inst = vcpu->arch.trapped_inst;
	u32 cp_num;
	cp_num = TRANSFER_BITSEG(8, 11, inst);
	if (cp_num == 15) {
		instr->Rn_index = TRANSFER_BITSEG(16, 19, inst);
		instr->Rd_index = TRANSFER_BITSEG(12, 15, inst);
		instr->opcode2 = TRANSFER_BITSEG(5, 7, inst);
		instr->return_info = emu_mrc(instr, vcpu);
	} else {
		printk("MRC with cp %d, which is not emulated.\n", cp_num);
	}
}

/**
  * @brief decode_mcrr decode "mcrr", then call function to emulate "mcrr"
  */
static void decode_mcrr(struct instruction *instr, struct kvm_vcpu *vcpu)
{
	u32 inst = vcpu->arch.trapped_inst;
	
	instr->Rn_index = TRANSFER_BITSEG(16, 19, inst);
	instr->Rd_index = TRANSFER_BITSEG(12, 15, inst);
	instr->imme = TRANSFER_BITSEG(0, 3, inst);
	instr->return_info = emu_mcrr(instr, vcpu);
}

/**
  * @brief decode coprocessor_related instruction. If it's MRRC/MCRR/LDC/STC, return error
  */
static int decode_copro_inst(u32 op)
{
	int return_value;
	switch (op & 0x1F) {
		case OP1_MRRC:
			printk("- KVM decoder get: MRRC, which should get from Undefined exception.\n");
			return_value = -1;
			goto out;
		case OP1_MCRR:
			printk("- KVM decoder get: MCRR, which should get from Undefined exception.\n");
			return_value = -1;
			goto out;
		default:
			if (op & 1) {
				printk(" dipatcher case: LDC\n");
				return_value = -1;
				goto out;
			} else {
				printk(" dipatcher case: STC\n");
				return_value = -1;
				goto out;
			}
			return_value = 0;
			goto out;
	}
out:
	return return_value;
}

/**
  * @brief decode undefine instruction, then printk and return error
  * 
  * All "privileged and sensitive" instructions have been trap into another dispatcher.
  * As a result, there should be no undefine instruction over here. If any instruction
  * passes thru here, it should have some problem. So we printk and return error here.
  */
static int decode_odd_undef_inst(u32 inst, struct kvm_vcpu *vcpu)
{
	int return_value = 0;
	switch (inst & 0x01100010) {
		case OP1_CDP_1:
		case OP1_CDP_2:
			printk(" dipatcher case: CDP\n");
			return_value = -1;
			goto out;
		case OP1_MCR:
			printk("get MCR trap from SWI, which should not exist. PC %08x\n", vcpu->arch.regs[REG_PC]);
			goto out;
		case OP1_MRC:
			printk("get MRC trap from SWI, which should not exist PC. %08x\n", vcpu->arch.regs[REG_PC]);
			goto out;
		case OP1_SWI_1: 
		case OP1_SWI_2:
		case OP1_SWI_3:
		case OP1_SWI_4:
			printk(" dipatcher case: SWI\n");
			return_value = -1;
			goto out;
		default:
			printk(" dispatcher: no instruction.\n");
			return_value = -1;
			goto out;
	}
out:
	return return_value;
}

/**
  * @brief Decode Multimedia Load/Store inst, then emulate it
  */
static int decode_mls_inst(struct instruction *instr, struct kvm_vcpu *vcpu, u32 inst)
{
	instr->Rn_index = TRANSFER_BITSEG(16, 19, inst);
	instr->opcode2 = TRANSFER_BITSEG(20, 22, inst) * 2;
	instr->opcode2 += TRANSFER_BITSEG(15, 15, inst);
	instr->return_info = emu_mls(vcpu->run, vcpu, instr, inst);
	return 0;
}

/**
  * @brief Decode Load/Store inst: "ldr,ldrb.ldrbt.ldrt.str.strb,strbt,strt", then emulate it
  */
static int decode_ls_rbt_inst(struct instruction *instr, struct kvm_vcpu *vcpu, u32 inst, u32 op)
{
	instr->opcode2 = op >> 1 & 0b1000;
	instr->opcode2 = instr->opcode2 | (op & 0b111);
	instr->Rd_index = TRANSFER_BITSEG(12, 15, inst);
	instr->Rn_index = TRANSFER_BITSEG(16, 19, inst);
	instr->return_info = emu_ls1(instr, inst, vcpu->run, vcpu);
	return 0;
}

/**
  * @brief Decode the instructions which use "msr" to access CPSR/SPSR, then emulate it 
  *
  * In this case, its op1 is catagoried as "Load/Store unsigned byte and word"
  * When it has to access CPSR/SPSR, we have to "trap and emulate" it.
  */
static int decode_msr_cpsr_data_inst(struct instruction *instr, struct kvm_vcpu *vcpu, u32 inst, u32 op)
{
                switch (op & 0x1F) {
                case OP1_NO_INST_1:
                        printk(" dispatcher case: no instr\n");
                        goto out;
                case OP1_NO_INST_2:
                        printk(" dispatcher case: no instr\n");
                        goto out;
                case OP1_MSR_CPSR:
                        instr->imme = immediate_generator(inst);
                        instr->return_info = emu_msr_cpsr(inst, vcpu, instr->imme);
                        goto out;
                case OP1_MSR_SPSR:
                        instr->imme = immediate_generator(inst);
                        instr->return_info = emu_msr_spsr(inst, vcpu, instr->imme);
                        goto out;
                default:
                        instr->imme = immediate_generator(inst);
                        instr->Rd_index = TRANSFER_BITSEG(12, 15, inst);
                        instr->Rn_index = TRANSFER_BITSEG(16, 19, inst);
                        instr->opcode2 = TRANSFER_BITSEG(21, 24, inst);
                        instr->s_data = test_bit(20, (void*)&inst);
                        instr->return_info = emu_data(instr, vcpu);
                        goto out;
		}
out:
		return 0;
}

/**
  * @brief decode the instructions which use "mrs/msr" to write the CPSR/SPSR, then emulate the inst
  */
static int decode_mrs_msr_cpsr_inst(struct instruction *instr, struct kvm_vcpu *vcpu, u32 inst, u32 op)
{	
	switch (op & 0x1F) {
		case OP1_MRS_W_CPSR: 
			instr->Rd_index = inst >> 12 & 0b1111;
			instr->return_info = emu_mrs_cpsr(instr, vcpu);
			goto out;
		case OP1_MRS_W_SPSR:
			instr->Rd_index = inst >> 12 & 0b1111; 
			instr->return_info = emu_mrs_spsr(instr, vcpu);
			goto out;
		case OP1_MSR_W_CPSR:
			instr->imme = vcpu->arch.regs[inst & 0b1111];
			instr->return_info = emu_msr_cpsr(inst, vcpu, instr->imme);
			goto out;
		case OP1_MSR_W_SPSR:
			instr->imme = vcpu->arch.regs[inst & 0b1111];
			instr->return_info = emu_msr_spsr(inst, vcpu, instr->imme);
			goto out;
		default:
			instr->imme = shift_imm_generator(inst, vcpu);
			instr->Rd_index = TRANSFER_BITSEG(12, 15, inst);
			instr->Rn_index = TRANSFER_BITSEG(16, 19, inst);
			instr->opcode2 = TRANSFER_BITSEG(21, 24, inst);
			instr->s_data = test_bit(20, (void*)&inst);
			instr->return_info = emu_data(instr, vcpu);
			goto out;
	}
out:
	return 0;    
}

/**
  * @brief decode BKPT instruction, then printk (we don't emulate BKPT)
  */
static int decode_bkpt_inst(u32 cond)
{
	if (cond == OP1_BKPT)
		printk(" dispatcher case BKPT\n");
	else 
		printk(" dispatcher no instruction\n");
	return -1;
}

/**
  * @brief decode LOAD/STORE inst.: SWP, SWPB, LDREX, STREX, then emulate them
  *
  * As the matter of fact, we don't really emulate SWP and SWPB
  */ 
static int decode_ls_rex_swpb_inst(struct instruction *instr, struct kvm_vcpu *vcpu, u32 inst, u32 op)
{
	int return_value;

	switch (op & 0x1F) {
		case OP1_SWP:
			printk(" dispatcher case SWP\n");
			return_value = -1;
			goto out;
		case OP1_SWPB:
			printk(" dispatcher case SWPB\n");
			return_value = -1;
			goto out;
		case OP1_LDREX:
			instr->Rd_index = TRANSFER_BITSEG(12, 15, inst);
			instr->Rn_index = TRANSFER_BITSEG(16, 19, inst);
			instr->imme = TRANSFER_BITSEG(0, 3, inst);
			instr->return_info = emu_ls_ldrex(instr, vcpu, inst);
			return_value = 0;
			goto out;
		case OP1_STREX:
			instr->Rd_index = TRANSFER_BITSEG(12, 15, inst);
			instr->Rn_index = TRANSFER_BITSEG(16, 19, inst);
			instr->imme = TRANSFER_BITSEG(0, 3, inst);
			instr->return_info = emu_ls_strex(instr, vcpu, inst);
			return_value = 0;
			goto out;
		default:
			printk(" dispatcher no instruction\n");
			return_value = -1;
			goto out;
	}
out:
	return return_value;
}

/**
  * @brief decode Data Process Instructions Depends on its case, we will decode more by deeper functions
  * 
  * 
  * @param *instr emulated instruction
  * @param *vcpu virtual cpu
  * 
  * @return emulation_success_or_not idicate that emulation is success or not
  */
static int decode_data_process_inst(struct instruction *instr, struct kvm_vcpu *vcpu, u32 inst, u32 op)
{
	int emulation_success_or_not;

	switch (inst >> 4 & 0xF) {
	case OP1_M_MRS_MSR_CPSR:
		emulation_success_or_not = decode_mrs_msr_cpsr_inst(instr, vcpu, inst, op);
		goto out;
	case OP1_M_BKPT:
		emulation_success_or_not = decode_bkpt_inst(instr->cond);
		goto out;
	case OP1_M_LS_REX_SWPB:
		emulation_success_or_not = decode_ls_rex_swpb_inst(instr, vcpu, inst, op);
		goto out;
	case OP1_M_LS_RH:
		instr->Rd_index = TRANSFER_BITSEG(12, 15, inst);
		if (op & 1) 
			instr->return_info = emu_ls_ldrh(instr, vcpu->run, vcpu, inst);
		else
			instr->return_info = emu_ls_strh(instr, vcpu->run, vcpu, inst);
		
		emulation_success_or_not = 0;
		goto out;
	case OP1_M_LDRSB:
		instr->Rd_index = TRANSFER_BITSEG(12, 15, inst);
		instr->Rn_index = TRANSFER_BITSEG(16, 19, inst);
		instr->opcode2 = TRANSFER_BITSEG(4, 7, inst);
		instr->return_info = emu_ls_ldrsb(instr, vcpu->run, vcpu, inst);
		emulation_success_or_not = 0;
		goto out;
	case OP1_M_LS_RSH_RD:
		instr->Rd_index = TRANSFER_BITSEG(12, 15, inst);
		if (op & 1) {
			instr->return_info = emu_ls_ldrsh(instr, vcpu->run, vcpu, inst);
		} else {
			instr->return_info = emu_ls_strd(instr, vcpu, inst);
		}
		emulation_success_or_not = 0;
		goto out;
	default:
		printk(" dispatcher case SWPB\n");
		KVM_BUG(1);
		emulation_success_or_not = 0;
		goto out;
	}
out:
	return emulation_success_or_not;
}

/**
  * @brief dispatcher dispatcher for critical instructions, then decode and emulate
  * 
  * @param *instr emulated instruction
  * @param *vcpu virtual cpu
  *
  * @return idicate that emualtion is success or failure
  */
int dispatcher(struct instruction *instr, struct kvm_vcpu *vcpu)
{
        u32 op = instr->opcode;
        u32 op_h = op >> 5 & 7; 
        u32 inst = vcpu->arch.trapped_inst;
	int emulation_success_or_not;

        switch (op_h) {
        case OP1_H_DATA_PROCESS:
		emulation_success_or_not = decode_data_process_inst(instr, vcpu, inst, op);
		goto out;
        case OP1_H_MSR_CPSR_DATA:
		emulation_success_or_not = decode_msr_cpsr_data_inst(instr, vcpu, inst, op);
		goto out;
	case OP1_H_LS_RBT_1:
	case OP1_H_LS_RBT_2:
		emulation_success_or_not = decode_ls_rbt_inst(instr, vcpu, inst, op);
		goto out;
	case OP1_H_MLS:
		emulation_success_or_not = decode_mls_inst(instr, vcpu, inst);
		goto out;
	case OP1_H_COPROCESSOR:
		emulation_success_or_not = decode_copro_inst(op);
		goto out;
        case OP1_H_UNDEFINE:
		emulation_success_or_not = decode_odd_undef_inst(inst, vcpu);
		goto out;
        default:
                emulation_success_or_not = -1;
		goto out;
        }
out:
	return emulation_success_or_not;
}

/**
  * @brief dispatcher_undef Dispatcher for "sensitive and privilged inst"
  *
  * Dispatcher for "sensitive and privilged inst." (aka. undefined inst)
  *
  * @param *instr instruction which should be emulated.
  * @param *vcpu virtual cpu
  *
  * @return emulation success or failure 
  *
  */
int dispatcher_undef(struct instruction *instr, struct kvm_vcpu *vcpu)
{
	u32 inst = vcpu->arch.trapped_inst;
	int result = 0;

	switch (inst & 0x0f100010) {
		case OP_ALL_MCR:
			decode_mcr(instr, vcpu);
			goto out;
		case OP_ALL_MRC:
			decode_mrc(instr, vcpu);
			goto out;
	}
	switch (inst & 0x0ff00000) {
		case OP_ALL_MCRR:
			decode_mcrr(instr, vcpu);
			goto out;
		case OP_ALL_MRRC:
			printk("- Undefined get: MRRC, which not simulated now.\n");
			result = -1;
			goto out;
		default:
			instr->return_info = EMULATE_FAIL;
			printk("emulate_undefined failed\n");
			printk("--Undefined exception, inst %x, addr, %x\n", inst, vcpu->arch.regs[15]);
			if (inst == 0xe1a00000) {
				printk("--Fake failed, continue.\n");
				goto out;
			}
			KVM_BUG(0);
	}
out:
	return result;
}

int special_cond(struct instruction *instr, struct kvm_vcpu *vcpu)
{
	u32 inst = vcpu->arch.trapped_inst;
	u32 test;
	if (instr->opcode == 0x10) {
		if(inst & OP_SETEND)
			KVM_BUG(1);
		else
			instr->return_info = emu_cps(inst, vcpu);
	}    
	test = instr->opcode & 0b11100101;
	if (test == OP_RFE)
		printk(" dispatcher case RFE\n");
	if (test == OP_SRS)
		printk(" dispatcher case SRS\n");
	return 0;
}

/**
  * @brief test_condition_code test instruction's condition code
  */
int test_condition_code(struct instruction *instr, struct kvm_vcpu *vcpu)
{
	u32 flag = vcpu->arch.virtual_cpsr;

	switch (instr->cond) { 
		case COND_EQ:
			return flag & PSR_Z_BIT ? 1 : 0; 
		case COND_NE:
			return !(flag & PSR_Z_BIT) ? 1 : 0; 
		case COND_CS:
			return flag & PSR_C_BIT ? 1 : 0; 
		case COND_CC:
			return !(flag & PSR_C_BIT) ? 1 : 0; 
		case COND_MI:
			return flag & PSR_N_BIT ? 1 : 0; 
		case COND_PL:
			return !(flag & PSR_N_BIT) ? 1 : 0; 
		case COND_VS:
			return flag & PSR_V_BIT ? 1 : 0; 
		case COND_VC:
			return !(flag & PSR_V_BIT) ? 1 : 0; 
		case COND_HI:
			return flag & PSR_C_BIT && !(flag & PSR_Z_BIT) ? 1 : 0; 
		case COND_LS:
			return !(flag & PSR_C_BIT) || flag & PSR_Z_BIT ? 1 : 0; 
		case COND_GE:
			return flag >> 3 &  flag & PSR_V_BIT ? 1 : 0; 
		case COND_LT:
			return !(flag >> 3 &  flag & PSR_V_BIT) ? 1 : 0; 
		case COND_GT:
			return !(flag & PSR_Z_BIT) && flag >> 3 & flag & PSR_V_BIT ? 1 : 0; 
		case COND_LE:
			return (flag & PSR_Z_BIT) && !(flag >> 3 & flag & PSR_V_BIT) ? 1 : 0; 
		case COND_AL:
			return 1;
		case COND_SPECIAL:
			special_cond(instr, vcpu);
			return 2;
		default:
			KVM_BUG(1);
	}    
}

/**
  * @brief kvmarm_emulate_instruction Main interface of instruction emulation
  *
  * This function is main interface of inst. emulation. Next steps of instruction
  * emulation is dispatch, decode, and emulation instructions.
  *
  * @param *vcpu virtual cpu
  * @param inst_type critical instructions or non critical instructions 
  *
  * @return return_info for resume back to guest
  */
int kvmarm_emulate_instruction(struct kvm_vcpu *vcpu, int inst_type)
{
        struct instruction instr;

        kvm_profiling_count(&vcpu->stat.emu_inst);
        sync_condition_code(vcpu);
        vcpu->arch.regs[REG_PC] += 0x4; 

	if (inst_type == NON_CRITICAL_INST) {
		dispatcher_undef(&instr, vcpu);
	} else {

		decode_opcode1(&instr, vcpu->arch.trapped_inst);

		switch (test_condition_code(&instr, vcpu)) {
		case 0:
			kvm_profiling_count(&vcpu->stat.cond_inst);
			return EMULATE_DONE;
		case 1:
			break;
		case 2:
			return instr.return_info;
		default:
			KVM_BUG(1);
		}    

		if (dispatcher(&instr, vcpu) == -1)
			KVM_BUG(1);
	}
        return instr.return_info;
}

