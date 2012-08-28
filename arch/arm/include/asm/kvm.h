/**
 *  @kvm.h
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

#ifndef __LINUX_KVM_ARM_H
#define __LINUX_KVM_ARM_H

#include <linux/types.h>

struct kvm_regs {
        __u32 gpr[16];
        __u32 cpsr;
        __u32 spsr;
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

};

struct kvm_debug_exit_arch {
};
/* for KVM_SET_GUEST_DEBUG */
struct kvm_guest_debug_arch {
};
struct kvm_sregs {
};

struct kvm_fpu {
};

#endif /* __LINUX_KVM_ARM_H */

