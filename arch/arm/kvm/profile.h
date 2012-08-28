/**
 *  @profile.h
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

#ifndef __PROFILE_H__
#define __PROFILE_H__

#ifdef CONFIG_PROFILE_MODEL
#include <asm/kvm_host.h>
struct kvm_vcpu;

void profile_init(struct kvm_vcpu *vcpu);

#ifdef CONFIG_PROFILE_COUNT
void profile_dump_count(struct kvm_vcpu *vcpu);
void profile_dump_count2(struct kvm_vcpu *vcpu);
#else
#define profile_dump_count(vcpu);
#endif

#ifdef CONFIG_PROFILE_PC
void profile_dump_pc(struct kvm_vcpu *vcpu);
#else
#define profile_dump_pc(vcpu);
#endif

void free_pc_record(struct inst_hit *head);

void free_pc_record_all(struct kvm_vcpu *vcpu);

#endif //CONFIG_PROFILE_MODEL
#endif //__PROFILE_H__
