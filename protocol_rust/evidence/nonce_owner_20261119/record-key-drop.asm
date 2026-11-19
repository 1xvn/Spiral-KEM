
/workspace/spiral-load-build/audit/spiral-lab:     file format elf64-x86-64


Disassembly of section .text:

00000000001caea0 <core::ptr::drop_glue::<core::option::Option<spiral_protocol::records::RecordKey>>>:
  1caea0:	48 89 f8             	mov    %rdi,%rax
  1caea3:	48 8b 3f             	mov    (%rdi),%rdi
  1caea6:	48 85 ff             	test   %rdi,%rdi
  1caea9:	0f 84 95 00 00 00    	je     1caf44 <core::ptr::drop_glue::<core::option::Option<spiral_protocol::records::RecordKey>>+0xa4>
  1caeaf:	c6 40 08 00          	movb   $0x0,0x8(%rax)
  1caeb3:	c6 40 09 00          	movb   $0x0,0x9(%rax)
  1caeb7:	c6 40 0a 00          	movb   $0x0,0xa(%rax)
  1caebb:	c6 40 0b 00          	movb   $0x0,0xb(%rax)
  1caebf:	c6 40 0c 00          	movb   $0x0,0xc(%rax)
  1caec3:	c6 40 0d 00          	movb   $0x0,0xd(%rax)
  1caec7:	c6 40 0e 00          	movb   $0x0,0xe(%rax)
  1caecb:	c6 40 0f 00          	movb   $0x0,0xf(%rax)
  1caecf:	c6 40 10 00          	movb   $0x0,0x10(%rax)
  1caed3:	c6 40 11 00          	movb   $0x0,0x11(%rax)
  1caed7:	c6 40 12 00          	movb   $0x0,0x12(%rax)
  1caedb:	c6 40 13 00          	movb   $0x0,0x13(%rax)
  1caedf:	c6 40 14 00          	movb   $0x0,0x14(%rax)
  1caee3:	c6 40 15 00          	movb   $0x0,0x15(%rax)
  1caee7:	c6 40 16 00          	movb   $0x0,0x16(%rax)
  1caeeb:	c6 40 17 00          	movb   $0x0,0x17(%rax)
  1caeef:	c6 40 18 00          	movb   $0x0,0x18(%rax)
  1caef3:	c6 40 19 00          	movb   $0x0,0x19(%rax)
  1caef7:	c6 40 1a 00          	movb   $0x0,0x1a(%rax)
  1caefb:	c6 40 1b 00          	movb   $0x0,0x1b(%rax)
  1caeff:	c6 40 1c 00          	movb   $0x0,0x1c(%rax)
  1caf03:	c6 40 1d 00          	movb   $0x0,0x1d(%rax)
  1caf07:	c6 40 1e 00          	movb   $0x0,0x1e(%rax)
  1caf0b:	c6 40 1f 00          	movb   $0x0,0x1f(%rax)
  1caf0f:	c6 40 20 00          	movb   $0x0,0x20(%rax)
  1caf13:	c6 40 21 00          	movb   $0x0,0x21(%rax)
  1caf17:	c6 40 22 00          	movb   $0x0,0x22(%rax)
  1caf1b:	c6 40 23 00          	movb   $0x0,0x23(%rax)
  1caf1f:	c6 40 24 00          	movb   $0x0,0x24(%rax)
  1caf23:	c6 40 25 00          	movb   $0x0,0x25(%rax)
  1caf27:	c6 40 26 00          	movb   $0x0,0x26(%rax)
  1caf2b:	c6 40 27 00          	movb   $0x0,0x27(%rax)
  1caf2f:	c6 07 00             	movb   $0x0,(%rdi)
  1caf32:	c6 47 01 00          	movb   $0x0,0x1(%rdi)
  1caf36:	c6 47 02 00          	movb   $0x0,0x2(%rdi)
  1caf3a:	c6 47 03 00          	movb   $0x0,0x3(%rdi)
  1caf3e:	ff 25 04 a0 10 00    	jmp    *0x10a004(%rip)        # 2d4f48 <free@GLIBC_2.2.5>
  1caf44:	c3                   	ret
