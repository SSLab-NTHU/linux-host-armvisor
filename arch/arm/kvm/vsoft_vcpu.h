/**
 *  @vsoft_vcpu.h
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


#ifndef __ARCH_ARM_VSOFT_VCPU_H__
#define __ARCH_ARM_VSOFT_VCPU_H__

#include "emulate_arm.h"

#define CRITICAL_INST 1
#define NON_CRITICAL_INST 0

void decode_opcode1(struct instruction *, u32);

int dispatcher(struct instruction *, struct kvm_vcpu *);
int dispatcher_undef(struct instruction *, struct kvm_vcpu *);

int test_cond(struct instruction *, struct kvm_vcpu *);
int special_cond(struct instruction *, struct kvm_vcpu *);

int kvmarm_emulate_instruction(struct kvm_vcpu *, int);

#endif
