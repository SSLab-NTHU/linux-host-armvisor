/**
 *  @kvm_asm.h
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

#ifndef __ARM_KVM_ASM_H__
#define __ARM_KVM_ASM_H__

extern u32 __old_vector_table[];
extern u32 __replace_vector_table[];
extern u32 VCPU_FLAG;
#define ARM_INTERRUPT_RESET 0
#define ARM_INTERRUPT_UNDEFINED 1
#define ARM_INTERRUPT_SOFTWARE 2
#define ARM_INTERRUPT_PREF_ABORT 3
#define ARM_INTERRUPT_DATA_ABORT 4
#define ARM_INTERRUPT_IRQ 5
#define ARM_INTERRUPT_FIQ 6
#define REALVIEW_MAX_INTERRUPT 7 
#define RESUME_HOST 1
#define RESUME_GUEST 0
#endif /* __ARM_KVM_ASM_H__ */
