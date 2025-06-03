/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

;; ****************************************************************************
;; -----------------
;; ARC start up file
;; -----------------
;; The startup code for the ARC family of processors does the following
;; before transferring control to user defined main label :
;;	1. Set sp to __stack_top (link time variable)
;;	2. Set fp to zero
;;	3. Zero out the bss section (for uninitialized globals)
;; After returning from main, the processor is halted and the pipeline is
;; flushed out
;; ****************************************************************************

.macro CPU_EARLY_SETUP
	; Disable alignment checking
	lr	r5, [status32]
	bset	r5, r5, 19
	kflag	r5

	;enable non-volatile region
	mov r5, 0xF0000002
	sr r5, [0x5e]

	; enable I-cache/D-cache
	lr	r5, [IC_CTRL]
	bclr	r5, r5, 0	; 0 - Enable, 1 is Disable
	sr	r5, [IC_CTRL]

	lr	r5, [DC_CTRL]
	bclr	r5, r5, 6	; Invalidate (discard w/o wback)
	bclr	r5, r5, 0	; Enable (+Inv)
	sr	r5, [DC_CTRL]
.endm

.section .ivt, "a", @progbits

; Helper macro to define weak symbols to include into interrupt vector table.
; User code may define those functions in them, so user function will be
; referenced in the IVT. By default all handlers point to _exit_halt - so they
; always cause application halt, because if application causes an exception or
; interrupt, but doesn't set a handler for it - something is wrong in
; application. Exception is "start" entry of IVT, which points to __start
; function.
#define IVT_ENTRY(name) \
    .word name `\
    .weak name `\
    .set name, _exit_halt

; handler's name,		number,	name,			offset in IVT (hex/dec)
.word _start			; 0	program entry point	0x0		0
IVT_ENTRY(memory_error)		; 1	memory_error		0x4		4
IVT_ENTRY(instruction_error)	; 2	instruction_error	0x8		8
IVT_ENTRY(EV_MachineCheck)	; 3	EV_MachineCheck		0xC		12
IVT_ENTRY(EV_TLBMissI)		; 4	EV_TLBMissI		0x10		16
IVT_ENTRY(EV_TLBMissD)		; 5	EV_TLBMissD		0x14		20
IVT_ENTRY(EV_ProtV)		; 6	EV_ProtV		0x18		24
IVT_ENTRY(EV_PrivilegeV)	; 7	EV_PrivilegeV		0x1C		28
IVT_ENTRY(EV_SWI)		; 8	EV_SWI			0x20		32
IVT_ENTRY(EV_Trap)		; 9	EV_Trap			0x24		36
IVT_ENTRY(EV_Extension)		; 10	EV_Extension		0x28		40
IVT_ENTRY(EV_DivZero)		; 11	EV_DivZero		0x2C		44
IVT_ENTRY(EV_DCError)		; 12	EV_DCError		0x30		48
IVT_ENTRY(EV_Maligned)		; 13	EV_Maligned		0x34		52
IVT_ENTRY(EV_Ex14)		; 14	unused			0x38		56
IVT_ENTRY(EV_Ex15)		; 15	unused			0x3C		60
IVT_ENTRY(IRQ_Timer0)		; 16	Timer 0			0x40		64
IVT_ENTRY(IRQ_Timer1)		; 17	Timer 1			0x44		68
IVT_ENTRY(IRQ_18)		; 18				0x48		72
IVT_ENTRY(IRQ_19)		; 19				0x4C		76
IVT_ENTRY(IRQ_20)		; 20				0x50		80

.section .text.__startup, "ax", @progbits

.global _start
.type _start, @function
.align 4

; Startup code for the ARC600, ARC700 and ARCv2 processors
; NOTE:  The following restrictions apply on zero overhead loops (other
; restrictions are not pertinent to this code)
; - loop end should be 4 instruction words away from the lp_count setting
;   instruction
; - loop body should have at least two instruction words
_start:
	CPU_EARLY_SETUP
	mov gp, __sdata_start

	mov_s r2, __sdata_start	; r2 = start of the bss section
	sub r3, __bss_end, r2	; r3 = size of the bss section in bytes
	; set up the loop counter register to the size (in words) of the bss section
	asr_s r13, r3
	asr.f lp_count, r13

	mov sp, __stack_top	; initialize stack pointer
	mov_s r3, 0
	; loop to zero out the bss.  Enter loop only if lp_count != 0
	lpnz .Lend_zbss
	st.ab r3, [r2, 4]	; zero out the word
	nop
	nop
.Lend_zbss:

	;; branch to main
	bl.d main
	mov fp, 0		; initialize frame pointer
				; r0 contains exit code
	j _exit_halt

.global _exit_halt
.type _exit_halt, @function
.align 4
_exit_halt:
				; r0 contains exit code
	flag 0x01
	nop
	nop
	nop
	j _exit_halt
	nop
