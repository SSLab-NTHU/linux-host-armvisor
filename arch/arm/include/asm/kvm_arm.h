/**
 *  @kvm_arm.h
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

#ifndef __ARM_KVM_ARM_H__
#define __ARM_KVM_ARM_H__

#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <asm/ptrace.h>

extern int __kvmarm_vcpu_run(struct kvm_vcpu *vcpu);
static inline void kvmarm_queue_sync_exception(struct kvm_vcpu *vcpu,unsigned int exception)
{
	vcpu->arch.pending_sync_exceptions = exception;
}

static inline void kvmarm_queue_async_exception(struct kvm_vcpu *vcpu,unsigned int exception)
{
	vcpu->arch.pending_async_exceptions = exception;
}

static inline void kvmarm_clear_sync_exception(struct kvm_vcpu *vcpu, int exception)
{
	vcpu->arch.pending_sync_exceptions = 0;
}

static inline void kvmarm_clear_async_exception(struct kvm_vcpu *vcpu, int exception)
{
	vcpu->arch.pending_async_exceptions = 0;
}

void kvmarm_check_and_deliver_exceptions(struct kvm_vcpu *vcpu, int num);
#endif /* __ARM_KVM_ARM_H__ */
