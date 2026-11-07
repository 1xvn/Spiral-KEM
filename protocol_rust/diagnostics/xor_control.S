.text
.globl xor_cancel_control
.type xor_cancel_control,@function
xor_cancel_control:
    vmovdqu 0(%rdi), %xmm0
    vmovdqu 16(%rdi), %xmm1
    vmovdqu 32(%rdi), %xmm2
    vmovdqa %xmm0, %xmm3
    vmovdqa %xmm1, %xmm4
    vmovdqa %xmm2, %xmm5
    subq $16, %rdx
    jz .Lcancel_tail
    ret
.Lcancel_tail:
    vpxor %xmm0, %xmm3, %xmm3
    vpxor %xmm1, %xmm4, %xmm4
    vpxor %xmm2, %xmm5, %xmm5
    vmovdqu %xmm3, 0(%rsi)
    vmovdqu %xmm4, 16(%rsi)
    vmovdqu %xmm5, 32(%rsi)
    vzeroupper
    ret
.size xor_cancel_control,.-xor_cancel_control
.globl xor_clear_control
.type xor_clear_control,@function
xor_clear_control:
    vmovdqu 0(%rdi), %xmm0
    vmovdqu 16(%rdi), %xmm1
    vmovdqu 32(%rdi), %xmm2
    vpxor %xmm0, %xmm0, %xmm0
    vpxor %xmm1, %xmm1, %xmm1
    vpxor %xmm2, %xmm2, %xmm2
    vmovdqu %xmm0, 0(%rsi)
    vmovdqu %xmm1, 16(%rsi)
    vmovdqu %xmm2, 32(%rsi)
    vzeroupper
    ret
.size xor_clear_control,.-xor_clear_control
.section .note.GNU-stack,"",@progbits
