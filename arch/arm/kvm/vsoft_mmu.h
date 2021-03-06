/**
 *  @vsoft_mmu.h
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

#ifndef __ARM_KVM_VSOFT_MMU_H__
#define __ARM_KVM_VSOFT_MMU_H__

int vsoft_mmu_page_fault(struct kvm_vcpu *vcpu, gva_t ttbr, u32 error_code);
void init_kvm_vector(struct kvm_vcpu *vcpu);

void reset_vector_table(struct kvm_vcpu *vcpu);
#endif /* __ARM_KVM_VSOFT_MMU_H__ */
