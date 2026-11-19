
/workspace/spiral-load-build/audit/spiral-lab:     file format elf64-x86-64


Disassembly of section .text:

00000000001e6010 <<spiral_protocol::records::Rx>::decode>:
  1e6010:	55                   	push   %rbp
  1e6011:	41 57                	push   %r15
  1e6013:	41 56                	push   %r14
  1e6015:	41 55                	push   %r13
  1e6017:	41 54                	push   %r12
  1e6019:	53                   	push   %rbx
  1e601a:	48 81 ec c8 00 00 00 	sub    $0xc8,%rsp
  1e6021:	49 89 f7             	mov    %rsi,%r15
  1e6024:	48 89 fb             	mov    %rdi,%rbx
  1e6027:	4c 8d 76 10          	lea    0x10(%rsi),%r14
  1e602b:	4c 8d 6e 48          	lea    0x48(%rsi),%r13
  1e602f:	48 8d 4e 38          	lea    0x38(%rsi),%rcx
  1e6033:	48 8d 76 40          	lea    0x40(%rsi),%rsi
  1e6037:	49 8d 47 49          	lea    0x49(%r15),%rax
  1e603b:	4c 89 b4 24 90 00 00 	mov    %r14,0x90(%rsp)
  1e6042:	00 
  1e6043:	4c 89 bc 24 98 00 00 	mov    %r15,0x98(%rsp)
  1e604a:	00 
  1e604b:	4c 89 ac 24 a0 00 00 	mov    %r13,0xa0(%rsp)
  1e6052:	00 
  1e6053:	48 89 8c 24 a8 00 00 	mov    %rcx,0xa8(%rsp)
  1e605a:	00 
  1e605b:	48 89 b4 24 b0 00 00 	mov    %rsi,0xb0(%rsp)
  1e6062:	00 
  1e6063:	48 89 44 24 68       	mov    %rax,0x68(%rsp)
  1e6068:	48 89 84 24 b8 00 00 	mov    %rax,0xb8(%rsp)
  1e606f:	00 
  1e6070:	f3 0f 6f 02          	movdqu (%rdx),%xmm0
  1e6074:	f3 0f 6f 4a 10       	movdqu 0x10(%rdx),%xmm1
  1e6079:	66 0f 7f 8c 24 80 00 	movdqa %xmm1,0x80(%rsp)
  1e6080:	00 00 
  1e6082:	66 0f 7f 44 24 70    	movdqa %xmm0,0x70(%rsp)
  1e6088:	41 b4 06             	mov    $0x6,%r12b
  1e608b:	41 80 7f 49 00       	cmpb   $0x0,0x49(%r15)
  1e6090:	75 1d                	jne    1e60af <<spiral_protocol::records::Rx>::decode+0x9f>
  1e6092:	49 8b 06             	mov    (%r14),%rax
  1e6095:	48 85 c0             	test   %rax,%rax
  1e6098:	74 15                	je     1e60af <<spiral_protocol::records::Rx>::decode+0x9f>
  1e609a:	4c 8b a4 24 80 00 00 	mov    0x80(%rsp),%r12
  1e60a1:	00 
  1e60a2:	49 83 fc 28          	cmp    $0x28,%r12
  1e60a6:	0f 83 22 01 00 00    	jae    1e61ce <<spiral_protocol::records::Rx>::decode+0x1be>
  1e60ac:	45 31 e4             	xor    %r12d,%r12d
  1e60af:	48 8d 7c 24 70       	lea    0x70(%rsp),%rdi
  1e60b4:	e8 b7 ad fe ff       	call   1d0e70 <core::ptr::drop_glue::<spiral_protocol::buffer::Buffer>>
  1e60b9:	49 8b 3e             	mov    (%r14),%rdi
  1e60bc:	48 85 ff             	test   %rdi,%rdi
  1e60bf:	0f 84 b5 00 00 00    	je     1e617a <<spiral_protocol::records::Rx>::decode+0x16a>
  1e60c5:	41 c6 47 18 00       	movb   $0x0,0x18(%r15)
  1e60ca:	41 c6 47 19 00       	movb   $0x0,0x19(%r15)
  1e60cf:	41 c6 47 1a 00       	movb   $0x0,0x1a(%r15)
  1e60d4:	41 c6 47 1b 00       	movb   $0x0,0x1b(%r15)
  1e60d9:	41 c6 47 1c 00       	movb   $0x0,0x1c(%r15)
  1e60de:	41 c6 47 1d 00       	movb   $0x0,0x1d(%r15)
  1e60e3:	41 c6 47 1e 00       	movb   $0x0,0x1e(%r15)
  1e60e8:	41 c6 47 1f 00       	movb   $0x0,0x1f(%r15)
  1e60ed:	41 c6 47 20 00       	movb   $0x0,0x20(%r15)
  1e60f2:	41 c6 47 21 00       	movb   $0x0,0x21(%r15)
  1e60f7:	41 c6 47 22 00       	movb   $0x0,0x22(%r15)
  1e60fc:	41 c6 47 23 00       	movb   $0x0,0x23(%r15)
  1e6101:	41 c6 47 24 00       	movb   $0x0,0x24(%r15)
  1e6106:	41 c6 47 25 00       	movb   $0x0,0x25(%r15)
  1e610b:	41 c6 47 26 00       	movb   $0x0,0x26(%r15)
  1e6110:	41 c6 47 27 00       	movb   $0x0,0x27(%r15)
  1e6115:	41 c6 47 28 00       	movb   $0x0,0x28(%r15)
  1e611a:	41 c6 47 29 00       	movb   $0x0,0x29(%r15)
  1e611f:	41 c6 47 2a 00       	movb   $0x0,0x2a(%r15)
  1e6124:	41 c6 47 2b 00       	movb   $0x0,0x2b(%r15)
  1e6129:	41 c6 47 2c 00       	movb   $0x0,0x2c(%r15)
  1e612e:	41 c6 47 2d 00       	movb   $0x0,0x2d(%r15)
  1e6133:	41 c6 47 2e 00       	movb   $0x0,0x2e(%r15)
  1e6138:	41 c6 47 2f 00       	movb   $0x0,0x2f(%r15)
  1e613d:	41 c6 47 30 00       	movb   $0x0,0x30(%r15)
  1e6142:	41 c6 47 31 00       	movb   $0x0,0x31(%r15)
  1e6147:	41 c6 47 32 00       	movb   $0x0,0x32(%r15)
  1e614c:	41 c6 47 33 00       	movb   $0x0,0x33(%r15)
  1e6151:	41 c6 47 34 00       	movb   $0x0,0x34(%r15)
  1e6156:	41 c6 47 35 00       	movb   $0x0,0x35(%r15)
  1e615b:	41 c6 47 36 00       	movb   $0x0,0x36(%r15)
  1e6160:	41 c6 47 37 00       	movb   $0x0,0x37(%r15)
  1e6165:	c6 07 00             	movb   $0x0,(%rdi)
  1e6168:	c6 47 01 00          	movb   $0x0,0x1(%rdi)
  1e616c:	c6 47 02 00          	movb   $0x0,0x2(%rdi)
  1e6170:	c6 47 03 00          	movb   $0x0,0x3(%rdi)
  1e6174:	ff 15 ce ed 0e 00    	call   *0xeedce(%rip)        # 2d4f48 <free@GLIBC_2.2.5>
  1e617a:	49 c7 06 00 00 00 00 	movq   $0x0,(%r14)
  1e6181:	48 8b 44 24 68       	mov    0x68(%rsp),%rax
  1e6186:	c6 00 01             	movb   $0x1,(%rax)
  1e6189:	48 c7 c0 ff ff ff ff 	mov    $0xffffffffffffffff,%rax
  1e6190:	44 88 23             	mov    %r12b,(%rbx)
  1e6193:	40 88 6b 01          	mov    %bpl,0x1(%rbx)
  1e6197:	48 89 43 08          	mov    %rax,0x8(%rbx)
  1e619b:	0f 28 44 24 30       	movaps 0x30(%rsp),%xmm0
  1e61a0:	0f 11 43 10          	movups %xmm0,0x10(%rbx)
  1e61a4:	48 8b 44 24 40       	mov    0x40(%rsp),%rax
  1e61a9:	48 89 43 20          	mov    %rax,0x20(%rbx)
  1e61ad:	48 c7 43 28 28 00 00 	movq   $0x28,0x28(%rbx)
  1e61b4:	00 
  1e61b5:	4c 89 6b 30          	mov    %r13,0x30(%rbx)
  1e61b9:	48 89 d8             	mov    %rbx,%rax
  1e61bc:	48 81 c4 c8 00 00 00 	add    $0xc8,%rsp
  1e61c3:	5b                   	pop    %rbx
  1e61c4:	41 5c                	pop    %r12
  1e61c6:	41 5d                	pop    %r13
  1e61c8:	41 5e                	pop    %r14
  1e61ca:	41 5f                	pop    %r15
  1e61cc:	5d                   	pop    %rbp
  1e61cd:	c3                   	ret
  1e61ce:	48 89 44 24 60       	mov    %rax,0x60(%rsp)
  1e61d3:	48 89 54 24 28       	mov    %rdx,0x28(%rsp)
  1e61d8:	48 8b 6c 24 78       	mov    0x78(%rsp),%rbp
  1e61dd:	48 8d 7c 24 30       	lea    0x30(%rsp),%rdi
  1e61e2:	ba 28 00 00 00       	mov    $0x28,%edx
  1e61e7:	48 89 ee             	mov    %rbp,%rsi
  1e61ea:	ff 15 c8 04 0f 00    	call   *0xf04c8(%rip)        # 2d66b8 <_DYNAMIC+0x1988>
  1e61f0:	80 7c 24 30 01       	cmpb   $0x1,0x30(%rsp)
  1e61f5:	75 10                	jne    1e6207 <<spiral_protocol::records::Rx>::decode+0x1f7>
  1e61f7:	44 0f b6 64 24 31    	movzbl 0x31(%rsp),%r12d
  1e61fd:	0f b6 6c 24 32       	movzbl 0x32(%rsp),%ebp
  1e6202:	e9 a8 fe ff ff       	jmp    1e60af <<spiral_protocol::records::Rx>::decode+0x9f>
  1e6207:	4c 8b 4c 24 50       	mov    0x50(%rsp),%r9
  1e620c:	49 8d 41 28          	lea    0x28(%r9),%rax
  1e6210:	49 39 c4             	cmp    %rax,%r12
  1e6213:	0f 85 93 fe ff ff    	jne    1e60ac <<spiral_protocol::records::Rx>::decode+0x9c>
  1e6219:	48 8b 54 24 58       	mov    0x58(%rsp),%rdx
  1e621e:	89 d0                	mov    %edx,%eax
  1e6220:	c1 e8 08             	shr    $0x8,%eax
  1e6223:	b1 01                	mov    $0x1,%cl
  1e6225:	41 2a 4d 00          	sub    0x0(%r13),%cl
  1e6229:	38 c1                	cmp    %al,%cl
  1e622b:	0f 85 7b fe ff ff    	jne    1e60ac <<spiral_protocol::records::Rx>::decode+0x9c>
  1e6231:	4c 89 e6             	mov    %r12,%rsi
  1e6234:	48 89 54 24 20       	mov    %rdx,0x20(%rsp)
  1e6239:	89 d0                	mov    %edx,%eax
  1e623b:	24 fe                	and    $0xfe,%al
  1e623d:	45 31 e4             	xor    %r12d,%r12d
  1e6240:	3c 10                	cmp    $0x10,%al
  1e6242:	0f 85 67 fe ff ff    	jne    1e60af <<spiral_protocol::records::Rx>::decode+0x9f>
  1e6248:	8b 44 24 42          	mov    0x42(%rsp),%eax
  1e624c:	0f b7 4c 24 46       	movzwl 0x46(%rsp),%ecx
  1e6251:	48 c1 e1 20          	shl    $0x20,%rcx
  1e6255:	48 09 c1             	or     %rax,%rcx
  1e6258:	48 8b 44 24 3a       	mov    0x3a(%rsp),%rax
  1e625d:	0f b7 54 24 38       	movzwl 0x38(%rsp),%edx
  1e6262:	48 0f a4 c1 10       	shld   $0x10,%rax,%rcx
  1e6267:	48 c1 e0 10          	shl    $0x10,%rax
  1e626b:	48 09 d0             	or     %rdx,%rax
  1e626e:	49 33 07             	xor    (%r15),%rax
  1e6271:	49 33 4f 08          	xor    0x8(%r15),%rcx
  1e6275:	48 09 c1             	or     %rax,%rcx
  1e6278:	0f 85 31 fe ff ff    	jne    1e60af <<spiral_protocol::records::Rx>::decode+0x9f>
  1e627e:	48 89 ea             	mov    %rbp,%rdx
  1e6281:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
  1e6286:	49 39 47 38          	cmp    %rax,0x38(%r15)
  1e628a:	0f 85 1f fe ff ff    	jne    1e60af <<spiral_protocol::records::Rx>::decode+0x9f>
  1e6290:	49 83 c1 f0          	add    $0xfffffffffffffff0,%r9
  1e6294:	80 7c 24 20 10       	cmpb   $0x10,0x20(%rsp)
  1e6299:	75 1e                	jne    1e62b9 <<spiral_protocol::records::Rx>::decode+0x2a9>
  1e629b:	49 8d 4f 40          	lea    0x40(%r15),%rcx
  1e629f:	48 8b 09             	mov    (%rcx),%rcx
  1e62a2:	4c 01 c9             	add    %r9,%rcx
  1e62a5:	48 81 f9 ff ff ff 3f 	cmp    $0x3fffffff,%rcx
  1e62ac:	76 0b                	jbe    1e62b9 <<spiral_protocol::records::Rx>::decode+0x2a9>
  1e62ae:	41 b4 08             	mov    $0x8,%r12b
  1e62b1:	40 b5 02             	mov    $0x2,%bpl
  1e62b4:	e9 f6 fd ff ff       	jmp    1e60af <<spiral_protocol::records::Rx>::decode+0x9f>
  1e62b9:	48 8b 4c 24 60       	mov    0x60(%rsp),%rcx
  1e62be:	8b 09                	mov    (%rcx),%ecx
  1e62c0:	48 0f c8             	bswap  %rax
  1e62c3:	89 4c 24 14          	mov    %ecx,0x14(%rsp)
  1e62c7:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
  1e62cc:	48 83 c6 d8          	add    $0xffffffffffffffd8,%rsi
  1e62d0:	4c 29 ce             	sub    %r9,%rsi
  1e62d3:	0f 82 4b 01 00 00    	jb     1e6424 <<spiral_protocol::records::Rx>::decode+0x414>
  1e62d9:	48 89 74 24 30       	mov    %rsi,0x30(%rsp)
  1e62de:	48 83 fe 10          	cmp    $0x10,%rsi
  1e62e2:	0f 85 57 01 00 00    	jne    1e643f <<spiral_protocol::records::Rx>::decode+0x42f>
  1e62e8:	48 8d 6a 28          	lea    0x28(%rdx),%rbp
  1e62ec:	49 8d 04 29          	lea    (%r9,%rbp,1),%rax
  1e62f0:	49 8d 7f 18          	lea    0x18(%r15),%rdi
  1e62f4:	48 89 04 24          	mov    %rax,(%rsp)
  1e62f8:	48 8d 74 24 14       	lea    0x14(%rsp),%rsi
  1e62fd:	b9 28 00 00 00       	mov    $0x28,%ecx
  1e6302:	49 89 e8             	mov    %rbp,%r8
  1e6305:	4d 89 cd             	mov    %r9,%r13
  1e6308:	e8 53 46 01 00       	call   1fa960 <<chacha20poly1305::ChaChaPoly1305<cipher::stream_wrapper::StreamCipherCoreWrapper<chacha20::ChaChaCore<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B1>, typenum::bit::B0>>>> as aead::AeadInPlace>::decrypt_in_place_detached>
  1e630d:	41 b4 01             	mov    $0x1,%r12b
  1e6310:	84 c0                	test   %al,%al
  1e6312:	48 8b 4c 24 28       	mov    0x28(%rsp),%rcx
  1e6317:	75 1e                	jne    1e6337 <<spiral_protocol::records::Rx>::decode+0x327>
  1e6319:	4c 8b 64 24 20       	mov    0x20(%rsp),%r12
  1e631e:	41 80 fc 11          	cmp    $0x11,%r12b
  1e6322:	75 54                	jne    1e6378 <<spiral_protocol::records::Rx>::decode+0x368>
  1e6324:	49 83 fd 01          	cmp    $0x1,%r13
  1e6328:	75 0a                	jne    1e6334 <<spiral_protocol::records::Rx>::decode+0x324>
  1e632a:	80 7d 00 02          	cmpb   $0x2,0x0(%rbp)
  1e632e:	0f 86 c9 00 00 00    	jbe    1e63fd <<spiral_protocol::records::Rx>::decode+0x3ed>
  1e6334:	45 31 e4             	xor    %r12d,%r12d
  1e6337:	c6 44 24 14 00       	movb   $0x0,0x14(%rsp)
  1e633c:	c6 44 24 15 00       	movb   $0x0,0x15(%rsp)
  1e6341:	c6 44 24 16 00       	movb   $0x0,0x16(%rsp)
  1e6346:	c6 44 24 17 00       	movb   $0x0,0x17(%rsp)
  1e634b:	c6 44 24 18 00       	movb   $0x0,0x18(%rsp)
  1e6350:	c6 44 24 19 00       	movb   $0x0,0x19(%rsp)
  1e6355:	c6 44 24 1a 00       	movb   $0x0,0x1a(%rsp)
  1e635a:	c6 44 24 1b 00       	movb   $0x0,0x1b(%rsp)
  1e635f:	c6 44 24 1c 00       	movb   $0x0,0x1c(%rsp)
  1e6364:	c6 44 24 1d 00       	movb   $0x0,0x1d(%rsp)
  1e6369:	c6 44 24 1e 00       	movb   $0x0,0x1e(%rsp)
  1e636e:	c6 44 24 1f 00       	movb   $0x0,0x1f(%rsp)
  1e6373:	e9 37 fd ff ff       	jmp    1e60af <<spiral_protocol::records::Rx>::decode+0x9f>
  1e6378:	49 8d 47 38          	lea    0x38(%r15),%rax
  1e637c:	f3 0f 6f 00          	movdqu (%rax),%xmm0
  1e6380:	66 49 0f 6e cd       	movq   %r13,%xmm1
  1e6385:	66 0f 6f 15 b3 74 e3 	movdqa -0x1c8b4d(%rip),%xmm2        # 1d840 <anon.cd037ad03524607ba3a649067cb061ba.1684.llvm.14803345400176126745+0x30>
  1e638c:	ff 
  1e638d:	66 0f 6c d1          	punpcklqdq %xmm1,%xmm2
  1e6391:	66 0f d4 d0          	paddq  %xmm0,%xmm2
  1e6395:	f3 0f 7f 10          	movdqu %xmm2,(%rax)
  1e6399:	48 8b 44 24 70       	mov    0x70(%rsp),%rax
  1e639e:	f3 0f 6f 41 08       	movdqu 0x8(%rcx),%xmm0
  1e63a3:	66 0f 7f 44 24 30    	movdqa %xmm0,0x30(%rsp)
  1e63a9:	48 8b 49 18          	mov    0x18(%rcx),%rcx
  1e63ad:	48 89 4c 24 40       	mov    %rcx,0x40(%rsp)
  1e63b2:	c6 44 24 14 00       	movb   $0x0,0x14(%rsp)
  1e63b7:	c6 44 24 15 00       	movb   $0x0,0x15(%rsp)
  1e63bc:	c6 44 24 16 00       	movb   $0x0,0x16(%rsp)
  1e63c1:	c6 44 24 17 00       	movb   $0x0,0x17(%rsp)
  1e63c6:	c6 44 24 18 00       	movb   $0x0,0x18(%rsp)
  1e63cb:	c6 44 24 19 00       	movb   $0x0,0x19(%rsp)
  1e63d0:	c6 44 24 1a 00       	movb   $0x0,0x1a(%rsp)
  1e63d5:	c6 44 24 1b 00       	movb   $0x0,0x1b(%rsp)
  1e63da:	c6 44 24 1c 00       	movb   $0x0,0x1c(%rsp)
  1e63df:	c6 44 24 1d 00       	movb   $0x0,0x1d(%rsp)
  1e63e4:	c6 44 24 1e 00       	movb   $0x0,0x1e(%rsp)
  1e63e9:	c6 44 24 1f 00       	movb   $0x0,0x1f(%rsp)
  1e63ee:	48 83 f8 ff          	cmp    $0xffffffffffffffff,%rax
  1e63f2:	0f 85 98 fd ff ff    	jne    1e6190 <<spiral_protocol::records::Rx>::decode+0x180>
  1e63f8:	e9 bc fc ff ff       	jmp    1e60b9 <<spiral_protocol::records::Rx>::decode+0xa9>
  1e63fd:	49 8d 47 38          	lea    0x38(%r15),%rax
  1e6401:	48 ff 00             	incq   (%rax)
  1e6404:	49 8d 47 49          	lea    0x49(%r15),%rax
  1e6408:	c6 00 01             	movb   $0x1,(%rax)
  1e640b:	4c 89 f7             	mov    %r14,%rdi
  1e640e:	e8 8d 4a fe ff       	call   1caea0 <core::ptr::drop_glue::<core::option::Option<spiral_protocol::records::RecordKey>>>
  1e6413:	48 8b 4c 24 28       	mov    0x28(%rsp),%rcx
  1e6418:	49 c7 06 00 00 00 00 	movq   $0x0,(%r14)
  1e641f:	e9 75 ff ff ff       	jmp    1e6399 <<spiral_protocol::records::Rx>::decode+0x389>
  1e6424:	48 8d 3d 6f 19 e5 ff 	lea    -0x1ae691(%rip),%rdi        # 37d9a <anon.b0aa66ea813b246d68cb43470ceed55c.26.llvm.3310378897112643768+0x1c2>
  1e642b:	48 8d 15 e6 ab 0e 00 	lea    0xeabe6(%rip),%rdx        # 2d1018 <anon.b0aa66ea813b246d68cb43470ceed55c.23.llvm.3310378897112643768+0x468>
  1e6432:	be 13 00 00 00       	mov    $0x13,%esi
  1e6437:	ff 15 ab eb 0e 00    	call   *0xeebab(%rip)        # 2d4fe8 <_DYNAMIC+0x2b8>
  1e643d:	eb 1d                	jmp    1e645c <<spiral_protocol::records::Rx>::decode+0x44c>
  1e643f:	48 8d 15 ca 96 e3 ff 	lea    -0x1c6936(%rip),%rdx        # 1fb10 <anon.3c9889170036edd0586f4aa014985f9e.5.llvm.13970900411785142696+0xe0>
  1e6446:	4c 8d 0d e3 ab 0e 00 	lea    0xeabe3(%rip),%r9        # 2d1030 <anon.b0aa66ea813b246d68cb43470ceed55c.23.llvm.3310378897112643768+0x480>
  1e644d:	48 8d 74 24 30       	lea    0x30(%rsp),%rsi
  1e6452:	31 ff                	xor    %edi,%edi
  1e6454:	31 c9                	xor    %ecx,%ecx
  1e6456:	ff 15 ac ec 0e 00    	call   *0xeecac(%rip)        # 2d5108 <_DYNAMIC+0x3d8>
  1e645c:	0f 0b                	ud2
  1e645e:	48 89 c3             	mov    %rax,%rbx
  1e6461:	c6 44 24 14 00       	movb   $0x0,0x14(%rsp)
  1e6466:	c6 44 24 15 00       	movb   $0x0,0x15(%rsp)
  1e646b:	c6 44 24 16 00       	movb   $0x0,0x16(%rsp)
  1e6470:	c6 44 24 17 00       	movb   $0x0,0x17(%rsp)
  1e6475:	c6 44 24 18 00       	movb   $0x0,0x18(%rsp)
  1e647a:	c6 44 24 19 00       	movb   $0x0,0x19(%rsp)
  1e647f:	c6 44 24 1a 00       	movb   $0x0,0x1a(%rsp)
  1e6484:	c6 44 24 1b 00       	movb   $0x0,0x1b(%rsp)
  1e6489:	c6 44 24 1c 00       	movb   $0x0,0x1c(%rsp)
  1e648e:	c6 44 24 1d 00       	movb   $0x0,0x1d(%rsp)
  1e6493:	c6 44 24 1e 00       	movb   $0x0,0x1e(%rsp)
  1e6498:	c6 44 24 1f 00       	movb   $0x0,0x1f(%rsp)
  1e649d:	48 8d 7c 24 70       	lea    0x70(%rsp),%rdi
  1e64a2:	e8 c9 a9 fe ff       	call   1d0e70 <core::ptr::drop_glue::<spiral_protocol::buffer::Buffer>>
  1e64a7:	48 89 df             	mov    %rbx,%rdi
  1e64aa:	e8 51 25 0e 00       	call   2c8a00 <_Unwind_Resume@plt>
  1e64af:	ff 15 53 eb 0e 00    	call   *0xeeb53(%rip)        # 2d5008 <_DYNAMIC+0x2d8>
