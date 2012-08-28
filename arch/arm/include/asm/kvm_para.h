/**
 *  @kvm_para.h
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

#ifndef __ARM_KVM_PARA_H__
#define __ARM_KVM_PARA_H__

#ifdef __KERNEL__
#include <linux/kvm_host.h>
#include <linux/kvm_types.h>
struct kvm_vcpu;

static inline int kvm_para_available(void)
{
	return 0;
}

static inline unsigned int kvm_arch_para_features(void)
{
	return 0;
}

struct kvm_guest_opt_regs {
	uint32_t cpsr;
	uint32_t c5_data;
	uint32_t c6_data;

	uint32_t svc_sp;
	uint32_t svc_lr;
	uint32_t svc_spsr;
	uint32_t usr_sp;
	uint32_t usr_lr;

	uint32_t vector_swi;
};

enum regs_type {
	VIRT_CPSR,
	VIRT_SVC_SPSR,
	VIRT_SVC_SP,
	VIRT_SVC_LR,
	VIRT_USR_SP,
	VIRT_USR_LR,
	VIRT_C5C6,
	VECTOR_SWI
};

struct fast_trap_entry {
	u32 pc, inst;
};

//MEM PV
int kvm_fill_pt_pv(struct kvm_vcpu *vcpu);
void kvm_free_pt_pv(struct kvm_vcpu *vcpu);

extern struct kvm_guest_opt_regs *kvm_virt_regs;

#ifdef CONFIG_CPU_OPT
void sync_to_opt_regs(enum regs_type type, struct kvm_vcpu *vcpu);
void sync_from_opt_regs(enum regs_type type, struct kvm_vcpu *vcpu);
#else
static inline void sync_to_opt_regs(enum regs_type type, struct kvm_vcpu *vcpu) {}
static inline void sync_from_opt_regs(enum regs_type type, struct kvm_vcpu *vcpu) {}
#endif /* CONFIG_CPU_OPT */

#endif /* __KERNEL__ */

#endif /* __ARM_KVM_PARA_H__ */
