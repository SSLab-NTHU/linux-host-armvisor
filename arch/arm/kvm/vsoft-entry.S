/**
 *  @vsoft-entry.S
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

#include <asm/assembler.h>
#include <asm/arm_asm.h>
#include <asm/page.h>
#include <asm/asm-offsets.h>

#define VCPU_REG(n)     (VCPU_REGS + (n * 4))
#define VCPU_HOST_REG(n)     (VCPU_HOST_REGS + (n * 4))

#define RESUME_GUEST 0
#define RESUME_HOST  1

@--> vector index
#define ARM_INTERRUPT_UNDEFINED 1
#define ARM_INTERRUPT_SOFTWARE 2
#define ARM_INTERRUPT_PREF_ABORT 3
#define ARM_INTERRUPT_DATA_ABORT 4
#define ARM_INTERRUPT_IRQ 5
#define ARM_INTERRUPT_FIQ 6

#define TTB_RGN_WBWA	(1 << 3)

#define BASE_ADDR 0xffff1800
#define TMP_SP_ADDR BASE_ADDR
#define VCPU_FLAG BASE_ADDR + 4
#define HOST_PGD  BASE_ADDR + 8
#define HOST_CONTEXT_ID BASE_ADDR + 12
#define VEC_IDX   BASE_ADDR + 16
#define JIFFIES_PTR BASE_ADDR + 20
#define KVM_TMP_VCPU_PTR BASE_ADDR + 24
#define ASM_PROFILE_ADDR 0xffff1e00
#define FAST_TRAP_TABLE_ADDR 0xffff1874

@-------------> key data structure

.globl __host_vector_table
__host_vector_table:
		.word 0
        .word 0xffff0380
        .word vector_swi
        .word 0xffff0300
        .word 0xffff0280
        .word 0
        .word 0xffff0200
        .word 0xffff0400

@ it will be initialed by kvm_arch_vcpu_create() in arm.c
.globl kvm_vcpu_pointer
kvm_vcpu_pointer:
	.word 0x0
.globl vcpu_flag_addr
vcpu_flag_addr:
    .word VCPU_FLAG

host_pgd_addr:
 	.word HOST_PGD
vector_index:
 	.word VEC_IDX
stored_lr:
 	.word 0
stored_spsr:
 	.word 0
irq_count:
	.word 0
.globl tmp_sp_addr
tmp_sp_addr:
	.word TMP_SP_ADDR

.globl relocate_guest_run
relocate_guest_run:
    .word 0xffff1600

virt_regs_ptr:
	.word CONFIG_VIRT_REGS_ADDR


@-------------> HANDLER_EXIT

@ r0 = vcpu pointer
@ r1 = exit number
@ r2 = tmp
@ r3 = tmp
@ all guest registers are stored in the SVC mode's stack
handle_exit:

        @modify vcpu_flag = 0
		mov r2,	#0
  	    	ldr r3,	vcpu_flag_addr
		str r2,	[r3]
		
        @r0 = vcpu
        @r1 = exit_nr
		bl kvmarm_handle_exit

        @after kvmarm_handle_exit
		cmp r0,	#RESUME_GUEST
		bne guest_stop
		b guest_run

@-------------> KVM_HANDLER

.macro store_to_vcpu_svc
		str lr, back_lr
		ldr lr, kvm_vcpu_pointer
		add lr, lr, #VCPU_REGS
		stmib lr, {r1 - r12}
		ldmia r0, {r1 - r3}
		str r1, [lr]
		add r0, lr, #S_PC
		str r2, [r0]
		ldr lr, back_lr
		stmdb   r0, {sp, lr}
		ldr sp, [sp, #-4]
		ldr r0, kvm_vcpu_pointer
		str r3, [r0, #VCPU_GUEST_SPSR]
		mrs r3, spsr
		str r3, [r0, #VCPU_GUEST_SVC_SPSR]
	back_lr:
		.word 0	
.endm

.macro store_to_vcpu_m

		ldr lr, kvm_vcpu_pointer
		add lr, lr, #VCPU_REGS
		stmib lr, {r1 - r12}
		ldmia r0, {r1 - r3}		
		str r1, [lr]
		add r0, lr, #S_PC
		str r2, [r0]		
	  	stmdb   r0, {sp, lr}^		
		sub lr, lr, #VCPU_REGS
		str r3, [lr, #VCPU_GUEST_SPSR]
.endm

@r0 = previous mode's sp
@--> sp = {r0, lr, spsr}
.macro store_to_vcpu mode

        @save this mode r0 and lr
		stmia	sp, {r0, lr}
        
        @save spsr
		mrs	lr, spsr 
		str	lr, [sp, #8]
		mov	r0, sp

    .ifc \mode, 1
		@ switch to SVC mode
        	cps #0x13
    .endif

    .ifc \mode, 2
		cps #0x13
		store_to_vcpu_svc
    .endif
    .ifnc \mode, 2
		store_to_vcpu_m
    .endif
.endm

handle_rec_dabt:
	ldr r0, vector_index
	str r4, [r0]
	
	ldr r0, kvm_vcpu_pointer
	@no last inst
	mov r1, #-1 
	str r1 ,[r0, #VCPU_LAST_INST]

	ldr r1, tmp_sp_addr
	ldr r0, [r1]
	sub r0, #24
	str r0, [r1]

	ldmdb sp, {r0, r1, r2, r3, r4, sp}
	store_to_vcpu 2

	b to_handle_exit

pre_handle_exit_swi:

   	ldr r0, kvm_vcpu_pointer
	str r1, [r0, #VCPU_LAST_INST]
	str r2, [r0, #VCPU_SWI_NUM] 

	mov r1, #0
	str r1, [r0, #VCPU_GUEST_SVC_SPSR]

	ldr r1, tmp_sp_addr
	ldr r0, [r1]
	sub r0, #24
	str r0, [r1]

	ldmdb sp, {r0, r1, r2, r3, r4, sp}
        store_to_vcpu 0

   	ldr r0, kvm_vcpu_pointer
        @r1 = vector_index (exit number)
        mov r1, #ARM_INTERRUPT_SOFTWARE

	b handle_exit

pre_handle_exit:

	ldr r0, vector_index
	str r4, [r0]

   	ldr r0, kvm_vcpu_pointer
        @trapped_inst is stored by first macro
	str r1 ,[r0, #VCPU_LAST_INST]

	mov r1, #0
	str r1, [r0, #VCPU_GUEST_SVC_SPSR]	

	ldr r1, tmp_sp_addr
	ldr r0, [r1]
	sub r0, #24
	str r0, [r1]

	ldmdb sp, {r0, r1, r2, r3, r4, sp}

        store_to_vcpu 1

to_handle_exit:
        @free to use the regisers
   	ldr r0, kvm_vcpu_pointer
	mrc p15, 0, r2 , c5 , c0 ,0 
	str r2,	[r0, #VCPU_GUEST_C5_DATA ]
	mrc p15, 0, r2 , c5 , c0 ,1
	str r2, [r0, #VCPU_GUEST_C5_INSN ]
	mrc p15, 0, r2,  c6, c0, 0 
	str r2,	[r0 ,#VCPU_GUEST_C6_DATA ]

        @r1 = vector_index (exit number)
	ldr r2, vector_index
	ldr r1, [r2]

	b handle_exit

@ the register state is still the guset trap state
@ four cases:
@ 1. go to old_vector
@ 2. guest_irq_handler
@ 3. pre_handle_exit_swi
@ 4. pre_handle_exit
	.macro kvm_handler name, offset, index, correction=0
	.globl kvm_handler_\name 
	.align 5
kvm_handler_\name:

        @check vcpu flag
	cmp r3, #0
        beq to_host_handler_\name	

        @save vector index
	ldr r4, =\index

        @guest trap : UND/SWI/PABT/DABT/IRQ/FIQ

        .ifc \index, ARM_INTERRUPT_SOFTWARE
	    b  pre_handle_exit_swi
        .else
            .if \correction
                sub	lr, lr, #\correction
            .endif
	    mrs r0, spsr
	    and r0, #0x1f
	    cmp r0, #0x13
	    beq handle_rec_dabt
            b  pre_handle_exit
	.endif	

to_host_handler_\name:   
		
		ldr r0, tmp_sp_addr
		ldr r1, [r0]
		sub r1, #24
		str r1, [r0]
		
		ldmdb sp, {r0, r1, r2, r3, r4, sp}
        	stmdb sp, {r0, pc} 
        @prepare the pc value to old vector
		ldr r0,	=__host_vector_table
		ldr r0,	[r0, #\offset]
		str r0,	[sp, #-4]		
		ldmdb sp, {r0, pc}
	.endm

	.globl __kvm_handlers_start
__kvm_handlers_start:
 	kvm_handler und, 0x04, ARM_INTERRUPT_UNDEFINED
	kvm_handler swi, 0x08, ARM_INTERRUPT_SOFTWARE
	kvm_handler pabt,0x0C, ARM_INTERRUPT_PREF_ABORT, 4
	kvm_handler dabt,0x10, ARM_INTERRUPT_DATA_ABORT, 8    
	kvm_handler irq, 0x18, ARM_INTERRUPT_IRQ, 4
	kvm_handler fiq, 0x14, ARM_INTERRUPT_FIQ, 4
	.globl __kvm_handlers_end
__kvm_handlers_end:

@-------------> STUB_HANDLER
@ prepare "trapped_inst" and "swi_num"
@ change host_pgd
@ jump to kvm_handler

	.macro kvm_vector_stub name, offset, type 
	.align 5

kvm_vector_\name:
        @store sp and use tmp sp 
		str sp,	kvm_guest_sp
		ldr sp,	kvm_tmp_sp
		ldr sp, [sp]
        
        @save some registers
	@ r0 : tmp
	@ r1 = last inst
	@ r2 = swi #
	@ r3 = vcpu flag
	@ r4 = vector index
		sub sp, #4
		stmdb sp, {r0, r1, r2, r3, r4}
        	ldr r0, kvm_guest_sp
		str r0, [sp]
		add sp, #4

		mov r0, sp
		add r0, #24
		ldr r1, kvm_tmp_sp
		str r0, [r1]

		@vcpu flag
		ldr r0, kvm_vcpu_flag
		ldr r3, [r0]
		cmp r3, #0
		beq to_kvm_handler_\name

.ifc \type, ARM_INTERRUPT_SOFTWARE
@must load instruction before we change the pgd! r6=swi_num ,r4=trapped_inst
prepare_swi:
        @last inst
	 	ldr r1, [lr]

        @get swi number
	 	ldr r2, [lr, #-4]
	 	bic r2, #0xff000000

#ifdef CONFIG_CPU_OPT
		@check fast trap
		cmp r2, #0x198
		beq fast_trap

#ifdef CONFIG_SWI_OPT
		cmp r2, #0
		bne check_hyper_call
		cmp r7, #78
		beq to_kvm
check_hyper_call:
		cmp r2, #0x190
		blt virt_deliver_swi
#endif /* CONFIG_SWI_OPT */
		cmp r2, #0x210
		beq virt_sync_cond_to_hw

		cmp r2, #0x214
		beq virt_sync_cond_from_hw

		cmp r2, #0x254
		beq virt_change_mode
#endif /* CONFIG_CPU_OPT */
to_kvm:
.endif

.ifc \type, ARM_INTERRUPT_DATA_ABORT
prepare_data_abt:
        @last inst
		ldr r1, [lr, #-8]
.endif
		
.ifc \type, ARM_INTERRUPT_UNDEFINED
prepare_undefine:
        @last inst
		ldr r1, [lr, #-4]!
.endif

change_host_pgd_\name:

        @set TTB 0 to host PGD
		ldr r0, kvm_host_pgd
		ldr r0, [r0]
	 	orr	r0, r0, #TTB_RGN_WBWA
		mcr	p15, 0, r0, c2, c0, 0
		mov r0, #0 
		mcr 	p15, 0, r0, c8, c7, 0           @ invalidate I & D TLB
		mcr	p15, 0, r0, c7, c5, 6		@ flush BTAC/BTB
	 	mcr	p15, 0, r0, c7, c10, 4		@ drain write buffer
	@set host context ID
		ldr    r0, stub_host_context_id
		ldr    r0, [r0]
		mcr    p15, 0, r0, c13, c0, 1

to_kvm_handler_\name:
        @jump to kvm handler
		ldr pc, [pc, #-4]
	.endm

	.globl __kvm_stubs_start
__kvm_stubs_start:
	kvm_vector_stub   irq,  0x18, ARM_INTERRUPT_IRQ 
        .long kvm_handler_irq
	kvm_vector_stub	  dabt, 0x10, ARM_INTERRUPT_DATA_ABORT 
        .long kvm_handler_dabt
	kvm_vector_stub	  pabt, 0x0C, ARM_INTERRUPT_PREF_ABORT 
        .long kvm_handler_pabt
	kvm_vector_stub   und,  0x04, ARM_INTERRUPT_UNDEFINED 
        .long kvm_handler_und
	kvm_vector_stub   fiq,  0x1c, ARM_INTERRUPT_FIQ 
        .long kvm_handler_fiq
	kvm_vector_stub	  swi,  0x08, ARM_INTERRUPT_SOFTWARE 
        .long kvm_handler_swi


	.align	5
kvm_guest_sp:
        .word 0
kvm_tmp_sp:
	.word TMP_SP_ADDR
kvm_host_pgd:
	.word HOST_PGD
kvm_vcpu_flag:
	.word VCPU_FLAG
stub_host_context_id:
        .word HOST_CONTEXT_ID
kvm_virt_regs_ptr:
	.word CONFIG_VIRT_REGS_ADDR
kvm_jiffies_ptr:
	.word JIFFIES_PTR
kvm_tmp_vcpu_pointer:
	.word KVM_TMP_VCPU_PTR
kvm_asm_info_ptr:
	.word ASM_PROFILE_ADDR

#ifdef CONFIG_CPU_OPT
kvm_fast_trap_table:
	.word FAST_TRAP_TABLE_ADDR

 	.equ kvm_smc_offset, emu_hole - smc - 0x8

	.align	5
fast_trap:
#ifdef CONFIG_PROFILE_COUNT
	ldr r0, kvm_asm_info_ptr
	ldr r1, [r0, #PROFILE_CACHE_INST]
	add r1, #1
	str r1, [r0, #PROFILE_CACHE_INST]
#endif /* CONFIG_PROFILE_COUNT */

	ldr r0, kvm_fast_trap_table
	mov r3, #0
loop:
	add r3, #1
	cmp r3, #30
	beq ret_guest_fast_trap
	ldr r1, [r0]
	cmp lr, r1
	add r0, #8
	bne loop

	ldr r2, [r0, #-4]		@ get instruction
	@ldr r2, =0xee070f15  @ c7, c5, 0
	@ldr r2, kvm_nop	@ nop

smc:
	mov r1, pc
	add r1, #kvm_smc_offset
	str r2, emu_hole		@ self modifying
	mcr p15, 0, r1, c7, c5, 1	@ invalidate I-Cache Entry
	mcr p15, 0, r1, c7, c10, 1	@ clean D-Cache Line
	mcr p15, 0, r1, c7, c10, 4	@ dsb
	mcr p15, 0, r1, c7, c5, 4	@ isb

ret_guest_fast_trap:
	ldr r1, kvm_tmp_sp
	ldr r0, [r1]
	sub r0, #24
	str r0, [r1]

	ldmdb sp, {r0, r1, r2, r3, r4, sp}
emu_hole:
	mov r0, r0
	movs pc, lr


#ifdef CONFIG_SWI_OPT
virt_deliver_swi:

#ifdef CONFIG_PROFILE_COUNT
	ldr r0, kvm_asm_info_ptr
	ldr r1, [r0, #PROFILE_TRUE_SWI]
	add r1, #1
	str r1, [r0, #PROFILE_TRUE_SWI]
#endif /* CONFIG_PROFILE_COUNT */
	ldr r0, kvm_virt_regs_ptr
	str lr, [r0, #VIRT_SVC_LR]
	mrs r2, spsr
	ldr r1, [r0, #VIRT_CPSR]
	and r2, #0xff000000
	and r1, #0x00ffffff
	orr r2, r1, r2
	str r2, [r0, #VIRT_SVC_SPSR]

	@modify virtual cpsr
	ldr r1, [r0, #VIRT_CPSR]
	and r1, #0xffffffe0
	orr r1, #0xC0
	orr r1, #0x13
	str r1, [r0, #VIRT_CPSR]

	ldr lr, [r0, #VECTOR_SWI]

	@reset domain
	mrc p15, #0, r1, c3, c0, #0
	and r1, #0xffff0fff
	orr r1, #0xd000	@CLIENT:MANAGER
	mcr p15, #0, r1, c3, c0, #0

	add r0, #VIRT_USR_SP
	stmia r0, {sp, lr}^
	ldr r0, kvm_virt_regs_ptr
	add r0, #VIRT_SVC_SP
	ldmia r0, {sp, lr}^

	b ret_guest_chmod
#endif /* CONFIG_SWI_OPT */

virt_sync_cond_to_hw:
#ifdef CONFIG_PROFILE_COUNT
	ldr r0, kvm_asm_info_ptr
	ldr r1, [r0, #PROFILE_SYNC_TO_HW]
	add r1, #1
	str r1, [r0, #PROFILE_SYNC_TO_HW]
#endif /* CONFIG_PROFILE_COUNT */
	ldr r0, kvm_virt_regs_ptr
	ldr r1, [r0, #VIRT_CPSR]
	and r1, #0xff000000
	mrs r2, spsr
	and r2, #0x00ffffff
	orr r2, r1, r2
	msr spsr_cxsf, r2
	b ret_guest_chmod

virt_sync_cond_from_hw:
#ifdef CONFIG_PROFILE_COUNT
	ldr r0, kvm_asm_info_ptr
	ldr r1, [r0, #PROFILE_SYNC_FROM_HW]
	add r1, #1
	str r1, [r0, #PROFILE_SYNC_FROM_HW]
#endif /* CONFIG_PROFILE_COUNT */
	ldr r0, kvm_virt_regs_ptr
	ldr r1, [r0, #VIRT_CPSR]
	and r1, #0x00ffffff
	mrs r2, spsr
	and r2, #0xff000000
	orr r2, r1, r2
	str r2, [r0, #VIRT_CPSR]
	b ret_guest_chmod

virt_change_mode:
#ifdef CONFIG_PROFILE_COUNT
	ldr r0, kvm_asm_info_ptr
	ldr r1, [r0, #PROFILE_CHMOD_EXITS]
	add r1, #1
	str r1, [r0, #PROFILE_CHMOD_EXITS]
#endif /* CONFIG_PROFILE_COUNT */

	ldr r0, kvm_virt_regs_ptr

	@sync condition code 
	ldr r1, [r0, #VIRT_CPSR]
	and r1, #0xff000000
	mrs r2, spsr
	and r2, #0x00ffffff
	orr r2, r1, r2
	msr spsr_cxsf, r2

	@reset domain
	@mrc p15, #0, r1, c3, c0, #0
	@and r1, #0xffff0fff
	@orr r1, #0x4000	@NA:CLIENT
	@mcr p15, #0, r1, c3, c0, #0

	@TLB flush
	mov r1, #0 
	mcr 	p15, 0, r1, c8, c6, 0           @ invalidate I & D TLB
	mcr 	p15, 0, r1, c8, c5, 0           @ invalidate I & D TLB
	mcr	p15, 0, r0, c7, c5, 6		@ flush BTAC/BTB

	ldr lr, [r0, #VIRT_SVC_LR]

ret_guest_chmod:

	ldr r1, kvm_tmp_sp
	ldr r0, [r1]
	sub r0, #24
	str r0, [r1]

	ldmdb sp, {r0, r1, r2, r3, r4, sp}
	movs pc, lr
#endif /* CONFIG_CPU_OPT */

	.globl __kvm_stubs_end
__kvm_stubs_end:

@-------------> GUEST_STOP
    
@r0 - struct kvm_vcpu
@resume host registers
guest_stop:
                ldr r0, kvm_vcpu_pointer


                ldr r1, [r0, #VCPU_HOST_CPSR]
                msr spsr, r1
    
                add r0, r0, #VCPU_HOST_REGS+S_R0 
                ldmia r0,       {r0-lr}

        @return 0
                mov r0, #0
                adds pc, lr, #4

@-------------> GUEST_RUN

@the following code should be put on the 2nd vector page
@IRQ/FIQ is still disable
@r0 = VCPU_REGS_BASE (from guest run) or 0x0 (from IRQ/FIQ)
@r1 = shadow pgd 

.globl guest_run_start
guest_run_start:
                str r1, backup_ttbr    @store r1 to NEW_TTBR
                str r3, backup_ctxt_id @store guest context id to backup

                cmp r4, #0
                bne __from_guest_svc_abt
                mov r1, #0
                str r1, backup_cpsr 
                ldmia r0, {r0-lr}^ 
                b __switch_to_guest

__from_guest_svc_abt:
                str lr, backup_pc
                mrs r1, spsr
                str r1, backup_cpsr
                msr spsr, r4  
                ldmia r0, {r0-lr}

__switch_to_guest:
                str r1, backup_r1   @store r1 to TEMP_R1
                str r2, backup_r2   @store r2 to TEMP_R2

                @ store host context id
                mrc p15, #0, r1, c13, c0, #1
                ldr r2, kvm_host_context_id
                str r1, [r2]

                @flush arch
                mov r1, #0
                mcr p15, 0, r1, c7, c5, 6           @ flush BTAC/BTB
                mcr p15, 0, r1, c7, c10, 4                   @ drain write buffer

                @change to shadow pgd
                ldr r1, backup_ttbr    @load NEW_TTBR to r1
                mcr p15, 0, r1, c2, c0, 0               @ set TTBR 0

                mov r1, #0
                mcr p15, 0, r1, c8, c7, 0               @ invalidate I & D TLB
                @restore guest context id
                ldr r1, backup_ctxt_id
                mcr p15, 0, r1, c13, c0, 1

                @check if guest dabt in svc
                ldr r1, backup_cpsr
                and r2, r1, #0x1f
                cmp r2, #0x13
                @msreq cpsr, r1
                beq restore_svc

                ldr r1, backup_r1
                ldr r2, backup_r2
                movs pc, lr @Do the branch
restore_svc:
                msr cpsr, r1
                ldr r1, backup_r1
                ldr r2, backup_r2
                ldr pc, backup_pc

backup_ttbr:
                .word 0
backup_r1:
                .word 0
backup_r2:
                .word 0
backup_pc:
                .word 0
backup_cpsr:
                .word 0
backup_ctxt_id:
                .word 0
kvm_host_context_id:
                .word HOST_CONTEXT_ID
jiffies_ptr:
        .word JIFFIES_PTR
guest_virt_regs_ptr:
        .word CONFIG_VIRT_REGS_ADDR
guest_vcpu_pointer:
        .word KVM_TMP_VCPU_PTR

.globl guest_run_end
guest_run_end:

@ guest_run

.globl  guest_run
guest_run:
                ldr r0, kvm_vcpu_pointer

        @ load guest cpsr to bank spsr
                ldr r1, [r0, #VCPU_GUEST_SPSR]
                msr spsr_cxsf, r1
        @ load guest pc to bank lr
                ldr lr, [r0, #VCPU_REGS + S_PC]

        @change vcpu flag = 1
                mov r2, #1
                ldr r1, vcpu_flag_addr
                str r2, [r1]

        @r1 = shadow pgd
        ldr r1, [r0, #VCPU_SHADOW_PGD_ADDR ]
        orr r1, r1, #TTB_RGN_WBWA

        @load guest context id
        ldr r3, [r0, #VCPU_GUEST_CTXT_ID]

                ldr r4, [r0, #VCPU_GUEST_SVC_SPSR]

        @r0 = VCPU_REGS_BASE
                add r0, r0, #VCPU_REGS + S_R0

        @r2 = relocate_guest_run
                ldr r2, relocate_guest_run
                mov pc, r2

.globl __kvmarm_vcpu_run
__kvmarm_vcpu_run:

store_host:
    @store host (r0 - r14) registers
        str r0, [r0, #VCPU_HOST_REG(0)]
        add r0, r0, #VCPU_HOST_REG(1)
        stmia r0, {r1-lr}

        @ store host pgd
    mrc p15, 0, r1, c2, c0
    ldr r2, host_pgd_addr
    str r1, [r2]

    @store host cpsr
        sub r0, r0, #VCPU_HOST_REG(1)
        mrs r1, cpsr
        str r1, [r0, #VCPU_HOST_CPSR]

    @ r0 = *vcpu pointer
        b guest_run



		
	.equ kvm_stub_offset, __kvm_vectors_start + 0x1000 - __kvm_stubs_start

	.globl __kvm_vectors_start
__kvm_vectors_start:
		.word 0
		b kvm_vector_und  + kvm_stub_offset
		b kvm_vector_swi  + kvm_stub_offset
		b kvm_vector_pabt + kvm_stub_offset
		b kvm_vector_dabt + kvm_stub_offset
		.word 0
		b kvm_vector_irq  + kvm_stub_offset
		b kvm_vector_fiq  + kvm_stub_offset

	.globl __kvm_vectors_end
__kvm_vectors_end:

