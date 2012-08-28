/**
 *  @profile.c
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

#ifndef __PROFILE_C__
#define __PROFILE_C__

#ifdef CONFIG_PROFILE_MODEL
#include <linux/kvm_host.h>

#ifdef CONFIG_PROFILE_COUNT
void kvm_profiling_count(u32 *instr)
{
	(*instr) ++;
}

void profile_dump_count(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_stat *stat = &vcpu->stat;
	struct asm_profiling_info *asm_info = vcpu->stat.asm_info;

	//Fast Trap
	u32 fast_trap = asm_info->chmod_exits + asm_info->true_swi 
		+ asm_info->cache_inst + asm_info->sync_cond_to_hw + asm_info->sync_cond_from_hw;
	//CPU
	u32 psr_inst = stat->msr_inst + stat->mrs_inst + stat->cps_inst;
	u32 sensitive_inst_trap = stat->cond_inst + stat->data_inst + psr_inst + stat->ls_inst
			+ stat->mls_inst + stat->exp_inst + stat->copr_inst - stat->mmio_trap;
	u32 total_cpu_overhead = sensitive_inst_trap + stat->int_trap + fast_trap;
	//MEM
	u32 kvm_dabt_trap = stat->data_translation_miss + stat->protection_fault + stat->mmio_trap;
	u32 kvm_pabt_trap = stat->inst_translation_miss;
	u32 total_dabt_trap = stat->true_dabt_trap + kvm_dabt_trap;
	u32 total_pabt_trap = stat->true_pabt_trap + kvm_pabt_trap;
	u32 total_mem_pv = stat->pv_write_pte + stat->pv_free_pte;
	u32 total_mem_overhead = total_dabt_trap + total_pabt_trap + total_mem_pv;
	//SUMMARY
	u32 total_kvm_trap = total_cpu_overhead + total_mem_overhead;
	u32 heavy_trap = stat->mmio_trap;
	u32 light_trap = total_kvm_trap - fast_trap - heavy_trap;
	
	printk("----------------------------------------------------------------\n");
	printk("#### KVM-ARM OVERHEAD SUMMARY ####\n");
	printk("----------------------------------------------------------------\n");
	printk("Total KVM Traps:                        %9d\n",total_kvm_trap);
	printk("  fast traps:                      	%9d\n",fast_trap);
	printk("  light traps:                      	%9d\n",light_trap);
	printk("  heavy traps:                      	%9d\n",heavy_trap);
	printk("----------------------------------------------------------------\n");
	printk("  total handle exit:                    %9d\n",vcpu->stat.handle_exit);
	printk("  emulation inst:           	        %9d\n",vcpu->stat.emu_inst);
	printk("----------------------------------------------------------------\n");
	printk("#### CPU VIRTUALIZATION OVERHEAD ####\n");
	printk("----------------------------------------------------------------\n");
	printk("Total CPU Overhead:			%9d\n",total_cpu_overhead);
	printk("sensitive inst exits:                   %9d\n",sensitive_inst_trap);
	printk("  0.condition code:                    	%9d\n",vcpu->stat.cond_inst);
	printk("  1.data processing:                    %9d\n",vcpu->stat.data_inst);
	printk("  2.status reg access:                  %9d\n",psr_inst);
	printk("  --> msr:                      	%9d\n",vcpu->stat.msr_inst);
	printk("  --> mrs:                      	%9d\n",vcpu->stat.mrs_inst);
	printk("  --> cps:                      	%9d\n",vcpu->stat.cps_inst);
	printk("  3.load & store:                      	%9d\n",vcpu->stat.ls_inst);
	printk("  4.load & store multiple:              %9d\n",vcpu->stat.mls_inst);
	printk("  5.exception generating:               %9d\n",vcpu->stat.exp_inst);
	printk("  6.coprocessor inst:                   %9d\n",vcpu->stat.copr_inst);
	printk("  --> cache:                      	%9d\n",vcpu->stat.cache_inst);
	printk("  --> tlb:                      	%9d\n",vcpu->stat.tlb_inst);
	printk("irq trap:	                   	%9d\n",vcpu->stat.int_trap);
	printk("----------------------------------------------------------------\n");
	printk("fast trap exits:                        %9d\n",fast_trap);
	printk("  cache_inst:				%9d\n",vcpu->stat.asm_info->cache_inst);
	printk("  true_swi:                             %9d\n",vcpu->stat.asm_info->true_swi);
	printk("  sync_cond_to_hw:                      %9d\n",vcpu->stat.asm_info->sync_cond_to_hw);
	printk("  sync_cond_from_hw:                    %9d\n",vcpu->stat.asm_info->sync_cond_from_hw);
	printk("  chmod_exits:                          %9d\n",vcpu->stat.asm_info->chmod_exits);
	printk("\n----------------------------------------------------------------\n");
	printk("#### MEMORY VIRTUALIZATION OVERHEAD ####\n");
	printk("----------------------------------------------------------------\n");
	printk("Total Memory Overhead:			%9d\n",total_mem_overhead);
	printk("Total DABT Trap:			%9d(%d)\n",total_dabt_trap,vcpu->stat.dabt_exits);
	printk("  true dabt trap:			%9d\n",vcpu->stat.true_dabt_trap);
	printk("  kvm dabt trap:			%9d\n",kvm_dabt_trap);
	printk("Total PABT Trap:			%9d(%d)\n",total_pabt_trap,vcpu->stat.pabt_exits);
	printk("  true pabt trap:			%9d\n",vcpu->stat.true_pabt_trap);
	printk("  kvm pabt trap:			%9d\n",kvm_pabt_trap);
	printk("Total Memory PV:			%9d\n",total_mem_pv);
	printk("  PV write_pte: 			%9d\n",vcpu->stat.pv_write_pte);
	printk("  PV free_pte:				%9d\n",vcpu->stat.pv_free_pte);
	printk("----------------------------------------------------------------\n");
	printk("Kvm Dabt Trap:				%9d\n",kvm_dabt_trap);
	printk("  data translation miss:		%9d\n",vcpu->stat.data_translation_miss);
	printk("  protection fault:			%9d\n",vcpu->stat.protection_fault);
	printk("  mmio trap:				%9d\n",vcpu->stat.mmio_trap);
	printk("Kvm Pabt Trap:				%9d\n",kvm_pabt_trap);
	printk("  inst translation miss:		%9d\n",vcpu->stat.inst_translation_miss);
	printk("----------------------------------------------------------------\n");
	printk("#### APPENDIX ####\n");
	printk("----------------------------------------------------------------\n");
	printk("sync from opt:				%9d\n",vcpu->stat.sync_from_opt);
	printk("sync to opt:				%9d\n",vcpu->stat.sync_to_opt);
}

void profile_dump_count2(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_stat *stat = &vcpu->stat;
	struct asm_profiling_info *asm_info = vcpu->stat.asm_info;

	//Fast Trap
	u32 fast_trap = asm_info->chmod_exits + asm_info->true_swi 
		+ asm_info->cache_inst + asm_info->sync_cond_to_hw + asm_info->sync_cond_from_hw;
	//CPU
	u32 psr_inst = stat->msr_inst + stat->mrs_inst + stat->cps_inst;
	u32 sensitive_inst_trap = stat->cond_inst + stat->data_inst + psr_inst + stat->ls_inst
			+ stat->mls_inst + stat->exp_inst + stat->copr_inst - stat->mmio_trap;
	u32 total_cpu_overhead = sensitive_inst_trap + stat->int_trap + fast_trap;
	//MEM
	u32 kvm_dabt_trap = stat->data_translation_miss + stat->protection_fault + stat->mmio_trap;
	u32 kvm_pabt_trap = stat->inst_translation_miss;
	u32 total_dabt_trap = stat->true_dabt_trap + kvm_dabt_trap;
	u32 total_pabt_trap = stat->true_pabt_trap + kvm_pabt_trap;
	u32 total_mem_pv = stat->pv_write_pte + stat->pv_free_pte;
	u32 total_mem_overhead = total_dabt_trap + total_pabt_trap + total_mem_pv;
	//SUMMARY
	u32 total_kvm_trap = total_cpu_overhead + total_mem_overhead;
	u32 heavy_trap = stat->mmio_trap;
	u32 light_trap = total_kvm_trap - fast_trap - heavy_trap;
	
	printk("----------------------------------------------------------------\n");
	printk("#### KVM-ARM OVERHEAD SUMMARY ####\n");
	printk("----------------------------------------------------------------\n");
	printk("Total KVM Traps:%d\n",total_kvm_trap);
	printk("  fast traps:%d\n",fast_trap);
	printk("  light traps:%d\n",light_trap);
	printk("  heavy traps:%d\n",heavy_trap);
	printk("----------------------------------------------------------------\n");
	printk("  total handle exit:%d\n",vcpu->stat.handle_exit);
	printk("  emulation inst:%d\n",vcpu->stat.emu_inst);
	printk("----------------------------------------------------------------\n");
	printk("#### CPU VIRTUALIZATION OVERHEAD ####\n");
	printk("----------------------------------------------------------------\n");
	printk("sensitive inst exits:%d\n",sensitive_inst_trap);
	printk("  0.condition code:%d\n",vcpu->stat.cond_inst);
	printk("  1.data processing:%d\n",vcpu->stat.data_inst);
	printk("  2.status reg access:%d\n",psr_inst);
	printk("  --> msr:%d\n",vcpu->stat.msr_inst);
	printk("  --> mrs:%d\n",vcpu->stat.mrs_inst);
	printk("  --> cps:%d\n",vcpu->stat.cps_inst);
	printk("  3.load & store:%d\n",vcpu->stat.ls_inst);
	printk("  4.load & store multiple:%d\n",vcpu->stat.mls_inst);
	printk("  5.exception generating:%d\n",vcpu->stat.exp_inst);
	printk("  6.coprocessor inst:%d\n",vcpu->stat.copr_inst);
	printk("  --> cache:%d\n",vcpu->stat.cache_inst);
	printk("  --> tlb:%d\n",vcpu->stat.tlb_inst);
	printk("irq trap:%d\n",vcpu->stat.int_trap);
	printk("----------------------------------------------------------------\n");
	printk("fast trap exits:%d\n",fast_trap);
	printk("  cache_inst:%d\n",vcpu->stat.asm_info->cache_inst);
	printk("  true_swi:%d\n",vcpu->stat.asm_info->true_swi);
	printk("  sync_cond_to_hw:%d\n",vcpu->stat.asm_info->sync_cond_to_hw);
	printk("  sync_cond_from_hw:%d\n",vcpu->stat.asm_info->sync_cond_from_hw);
	printk("  chmod_exits:%d\n",vcpu->stat.asm_info->chmod_exits);
	printk("\n----------------------------------------------------------------\n");
	printk("#### MEMORY VIRTUALIZATION OVERHEAD ####\n");
	printk("----------------------------------------------------------------\n");
	printk("Total Memory Overhead:%d\n",total_mem_overhead);
	printk("Total DABT Trap:%d\n",total_dabt_trap,vcpu->stat.dabt_exits);
	printk("  true dabt trap:%d\n",vcpu->stat.true_dabt_trap);
	printk("  kvm dabt trap:%d\n",kvm_dabt_trap);
	printk("Total PABT Trap:%d\n",total_pabt_trap,vcpu->stat.pabt_exits);
	printk("  true pabt trap:%d\n",vcpu->stat.true_pabt_trap);
	printk("  kvm pabt trap:%d\n",kvm_pabt_trap);
	printk("Total Memory PV:%d\n",total_mem_pv);
	printk("  PV write_pte:%d\n",vcpu->stat.pv_write_pte);
	printk("  PV free_pte:%d\n",vcpu->stat.pv_free_pte);
	printk("----------------------------------------------------------------\n");
	printk("Kvm Dabt Trap:%d\n",kvm_dabt_trap);
	printk("  data translation miss:%d\n",vcpu->stat.data_translation_miss);
	printk("  protection fault:%d\n",vcpu->stat.protection_fault);
	printk("  mmio trap:%d\n",vcpu->stat.mmio_trap);
	printk("Kvm Pabt Trap:%d\n",kvm_pabt_trap);
	printk("  inst translation miss:%d\n",vcpu->stat.inst_translation_miss);
	printk("----------------------------------------------------------------\n");
	printk("#### APPENDIX ####\n");
	printk("----------------------------------------------------------------\n");
	printk("sync from opt:%d\n",vcpu->stat.sync_from_opt);
	printk("sync to opt:%d\n",vcpu->stat.sync_to_opt);
}

#endif

#ifdef CONFIG_PROFILE_PC
void kvm_profiling_pc(struct inst_hit **info_head, u32 pc)
{
	struct inst_hit *curr, *last;

	if (*info_head == NULL) {
		*info_head = (struct inst_hit *)kzalloc(sizeof(struct inst_hit), GFP_KERNEL);
		(*info_head)->pc = 0;
		(*info_head)->count = 0;
		(*info_head)->next = NULL;
	}

	curr = *info_head;
	while (curr != NULL) {
		last = curr;
		if (curr->pc == pc)
			break;
		curr = curr->next;
	}

	if (curr == NULL) {
		curr = (struct inst_hit *)kzalloc(sizeof(struct inst_hit), GFP_KERNEL);
		last->next = curr;
		curr->pc = pc;
		curr->count = 0;
		curr->next = NULL;
	}
	curr->count++;
}

void profile_dump_pc(struct kvm_vcpu *vcpu)
{
	printk("----------------------sensitive profiling-----------------------\n");
	struct inst_hit *ptr = vcpu->stat.copr_info;

	if (ptr != NULL)
		ptr = ptr->next;

	while (ptr != NULL) {
		printk("copr---> pc : %x count: %d\n", ptr->pc, ptr->count);
		ptr = ptr->next;
	}
}

#endif

void free_pc_record(struct inst_hit *head)
{
	struct inst_hit *curr, *next;
	curr = head;

	while (curr != NULL) {
		next = curr->next;
		kfree(curr);
		curr = next;
	}
}

void free_pc_record_all(struct kvm_vcpu *vcpu)
{
	free_pc_record(vcpu->stat.mmio_info);
	free_pc_record(vcpu->stat.copr_info);
	free_pc_record(vcpu->stat.mcr_info);
	free_pc_record(vcpu->stat.cps_info);
	free_pc_record(vcpu->stat.msr_info);
	free_pc_record(vcpu->stat.mrs_info);
	free_pc_record(vcpu->stat.mls_info);
	free_pc_record(vcpu->stat.data_info);
}

#endif //CONFIG_PROFILE_MODEL
#endif //__PROFILE_C__
