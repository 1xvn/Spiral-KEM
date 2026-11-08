	.file	"arm_client_probe.3f908e57d02af335-cgu.0"
	.section	.text.mark_probe,"ax",@progbits
	.globl	mark_probe
	.p2align	2
	.type	mark_probe,@function
mark_probe:
	.cfi_startproc
	mov	w8, #1
	movk	w8, #19779, lsl #16
	stp	x8, x0, [sp, #-48]!
	.cfi_def_cfa_offset 48
	mov	w8, #32
	stp	xzr, xzr, [sp, #32]
	mov	x3, xzr
	stp	x8, xzr, [sp, #16]
	mov	x4, sp
	//APP
	ror	x12, x12, #3
	ror	x12, x12, #13
	ror	x12, x12, #51
	ror	x12, x12, #61
	orr	x10, x10, x10
	//NO_APP
	add	sp, sp, #48
	.cfi_def_cfa_offset 0
	ret
.Lfunc_end0:
	.size	mark_probe, .Lfunc_end0-mark_probe
	.cfi_endproc

	.ident	"rustc version 1.99.1 (58cf8f9c3 2026-10-13)"
	.section	".note.GNU-stack","",@progbits
