#as: -J
#objdump: -dw
#name: i386 x86_64
#stderr: x86_64.e
.*: +file format .*

Disassembly of section .text:

0+ <.*>:
[ 	]+0:	01 ca[ 	]+add[ 	]+%ecx,%edx
[ 	]+2:	44 01 ca[ 	]+add[ 	]+%r9d,%edx
[ 	]+5:	41 01 ca[ 	]+add[ 	]+%ecx,%r10d
[ 	]+8:	48 01 ca[ 	]+add[ 	]+%rcx,%rdx
[ 	]+b:	4d 01 ca[ 	]+add[ 	]+%r9,%r10
[ 	]+e:	41 01 c0[ 	]+add[ 	]+%eax,%r8d
[ 	]+11:	66 41 01 c0[ 	]+add[ 	]+%ax,%r8w
[ 	]+15:	49 01 c0[ 	]+add[ 	]+%rax,%r8
[ 	]+18:	05 11 22 33 44[ 	]+add[ 	]+\$0x44332211,%eax
[ 	]+1d:	48 05 11 22 33 f4[ 	]+add[ 	]+\$0xf+4332211,%rax
[ 	]+23:	66 05 33 44[ 	]+add[ 	]+\$0x4433,%ax
[ 	]+27:	48 05 11 22 33 44[ 	]+add[ 	]+\$0x44332211,%rax
[ 	]+2d:	00 ca[ 	]+add[ 	]+%cl,%dl
[ 	]+2f:	00 f7[ 	]+add[ 	]+%dh,%bh
[ 	]+31:	40 00 f7[ 	]+add[ 	]+%sil,%dil
[ 	]+34:	41 00 f7[ 	]+add[ 	]+%sil,%r15b
[ 	]+37:	44 00 f7[ 	]+add[ 	]+%r14b,%dil
[ 	]+3a:	45 00 f7[ 	]+add[ 	]+%r14b,%r15b
[ 	]+3d:	50[ 	]+push[ 	]+%rax
[ 	]+3e:	41 50[ 	]+push[ 	]+%r8
[ 	]+40:	41 59[ 	]+pop[ 	]+%r9
[ 	]+42:	04 11[ 	]+add[ 	]+\$0x11,%al
[ 	]+44:	80 c4 11[ 	]+add[ 	]+\$0x11,%ah
[ 	]+47:	40 80 c4 11[ 	]+add[ 	]+\$0x11,%spl
[ 	]+4b:	41 80 c0 11[ 	]+add[ 	]+\$0x11,%r8b
[ 	]+4f:	41 80 c4 11[ 	]+add[ 	]+\$0x11,%r12b
[ 	]+53:	0f 20 c0[ 	]+mov[ 	]+%cr0,%rax
[ 	]+56:	41 0f 20 c0[ 	]+mov[ 	]+%cr0,%r8
[ 	]+5a:	44 0f 20 c0[ 	]+mov[ 	]+%cr8,%rax
[ 	]+5e:	44 0f 22 c0[ 	]+mov[ 	]+%rax,%cr8
[ 	]+62:	f3 48 a5[ 	]+rep movsq %ds:\(%rsi\),%es:\(%rdi\)
[ 	]+65:	f3 66 a5[ 	]+rep movsw %ds:\(%rsi\),%es:\(%rdi\)
[ 	]+68:	f3 48 a5[ 	]+rep movsq %ds:\(%rsi\),%es:\(%rdi\)
[ 	]+6b:	b0 11[ 	]+mov[ 	]+\$0x11,%al
[ 	]+6d:	b4 11[ 	]+mov[ 	]+\$0x11,%ah
[ 	]+6f:	40 b4 11[ 	]+mov[ 	]+\$0x11,%spl
[ 	]+72:	41 b4 11[ 	]+mov[ 	]+\$0x11,%r12b
[ 	]+75:	b8 44 33 22 11[ 	]+mov[ 	]+\$0x11223344,%eax
[ 	]+7a:	41 b8 44 33 22 11[ 	]+mov[ 	]+\$0x11223344,%r8d
[ 	]+80:	48 b8 88 77 66 55 44 33 22 11 	mov[ 	]+\$0x1122334455667788,%rax
[ 	]+8a:	49 b8 88 77 66 55 44 33 22 11 	mov[ 	]+\$0x1122334455667788,%r8
[ 	]+94:	03 00[ 	]+add[ 	]+\(%rax\),%eax
[ 	]+96:	41 03 00[ 	]+add[ 	]+\(%r8\),%eax
[ 	]+99:	45 03 00[ 	]+add[ 	]+\(%r8\),%r8d
[ 	]+9c:	49 03 00[ 	]+add[ 	]+\(%r8\),%rax
[ 	]+9f:	03 05 22 22 22 22[ 	]+add[ 	]+572662306\(%rip\),%eax.*
[ 	]+a5:	03 45 00[ 	]+add[ 	]+0x0\(%rbp\),%eax
[ 	]+a8:	03 04 25 22 22 22 22 	add[ 	]+0x22222222,%eax
[ 	]+af:	41 03 45 00[ 	]+add[ 	]+0x0\(%r13\),%eax
[ 	]+b3:	03 04 80[ 	]+add[ 	]+\(%rax,%rax,4\),%eax
[ 	]+b6:	41 03 04 80[ 	]+add[ 	]+\(%r8,%rax,4\),%eax
[ 	]+ba:	45 03 04 80[ 	]+add[ 	]+\(%r8,%rax,4\),%r8d
[ 	]+be:	43 03 04 80[ 	]+add[ 	]+\(%r8,%r8,4\),%eax
[ 	]+c2:	46 01 04 81[ 	]+add[ 	]+%r8d,\(%rcx,%r8,4\)
[ 	]+c6:	03 14 c0[ 	]+add[ 	]+\(%rax,%rax,8\),%edx
[ 	]+c9:	03 14 c8[ 	]+add[ 	]+\(%rax,%rcx,8\),%edx
[ 	]+cc:	03 14 d0[ 	]+add[ 	]+\(%rax,%rdx,8\),%edx
[ 	]+cf:	03 14 d8[ 	]+add[ 	]+\(%rax,%rbx,8\),%edx
[ 	]+d2:	03 10[ 	]+add[ 	]+\(%rax\),%edx
[ 	]+d4:	03 14 e8[ 	]+add[ 	]+\(%rax,%rbp,8\),%edx
[ 	]+d7:	03 14 f0[ 	]+add[ 	]+\(%rax,%rsi,8\),%edx
[ 	]+da:	03 14 f8[ 	]+add[ 	]+\(%rax,%rdi,8\),%edx
[ 	]+dd:	42 03 14 c0[ 	]+add[ 	]+\(%rax,%r8,8\),%edx
[ 	]+e1:	42 03 14 c8[ 	]+add[ 	]+\(%rax,%r9,8\),%edx
[ 	]+e5:	42 03 14 d0[ 	]+add[ 	]+\(%rax,%r10,8\),%edx
[ 	]+e9:	42 03 14 d8[ 	]+add[ 	]+\(%rax,%r11,8\),%edx
[ 	]+ed:	42 03 14 e0[ 	]+add[ 	]+\(%rax,%r12,8\),%edx
[ 	]+f1:	42 03 14 e8[ 	]+add[ 	]+\(%rax,%r13,8\),%edx
[ 	]+f5:	42 03 14 f0[ 	]+add[ 	]+\(%rax,%r14,8\),%edx
[ 	]+f9:	42 03 14 f8[ 	]+add[ 	]+\(%rax,%r15,8\),%edx
[ 	]+fd:	83 c1 11[ 	]+add[ 	]+\$0x11,%ecx
 100:	83 00 11[ 	]+addl[ 	]+\$0x11,\(%rax\)
 103:	48 83 00 11[ 	]+addq[ 	]+\$0x11,\(%rax\)
 107:	41 83 00 11[ 	]+addl[ 	]+\$0x11,\(%r8\)
 10b:	83 04 81 11[ 	]+addl[ 	]+\$0x11,\(%rcx,%rax,4\)
 10f:	41 83 04 81 11[ 	]+addl[ 	]+\$0x11,\(%r9,%rax,4\)
 114:	42 83 04 81 11[ 	]+addl[ 	]+\$0x11,\(%rcx,%r8,4\)
 119:	83 05 22 22 22 22 33 	addl[ 	]+\$0x33,572662306\(%rip\).*
 120:	48 83 05 22 22 22 22 33 	addq[ 	]+\$0x33,572662306\(%rip\).*
 128:	81 05 22 22 22 22 33 33 33 33 	addl[ 	]+\$0x33333333,572662306\(%rip\).*
 132:	48 81 05 22 22 22 22 33 33 33 33 	addq[ 	]+\$0x33333333,572662306\(%rip\).*
 13d:	83 04 c5 22 22 22 22 33 	addl[ 	]+\$0x33,0x22222222\(,%rax,8\)
 145:	83 80 22 22 22 22 33 	addl[ 	]+\$0x33,0x22222222\(%rax\)
 14c:	83 80 22 22 22 22 33 	addl[ 	]+\$0x33,0x22222222\(%rax\)
 153:	41 83 04 e8 33[ 	]+addl[ 	]+\$0x33,\(%r8,%rbp,8\)
 158:	83 04 25 22 22 22 22 33 	addl[ 	]+\$0x33,0x22222222
 160:	a0 11 22 33 44 55 66 77 88 	mov[ 	]+0x8877665544332211,%al
 169:	a1 11 22 33 44 55 66 77 88 	mov[ 	]+0x8877665544332211,%eax
 172:	a2 11 22 33 44 55 66 77 88 	mov[ 	]+%al,0x8877665544332211
 17b:	a3 11 22 33 44 55 66 77 88 	mov[ 	]+%eax,0x8877665544332211
 184:	48 a1 11 22 33 44 55 66 77 88 	mov[ 	]+0x8877665544332211,%rax
 18e:	48 a3 11 22 33 44 55 66 77 88 	mov[ 	]+%rax,0x8877665544332211
 198:	48 99[ 	]+cqto[ 	]+
 19a:	48 98[ 	]+cltq[ 	]+
 19c:	48 63 c0[ 	]+movslq %eax,%rax
 19f:	48 0f bf c0[ 	]+movswq %ax,%rax
 1a3:	48 0f be c0[ 	]+movsbq %al,%rax

0+1a7 <bar>:
 1a7:	b0 00[ 	]+mov[ 	]+\$0x0,%al
 1a9:	66 b8 00 00[ 	]+mov[ 	]+\$0x0,%ax
 1ad:	b8 00 00 00 00[ 	]+mov[ 	]+\$0x0,%eax
 1b2:	48 c7 c0 00 00 00 00 	mov[ 	]+\$0x0,%rax
 1b9:	a1 00 00 00 00 00 00 00 00 	mov[ 	]+0x0,%eax
 1c2:	8b 04 25 00 00 00 00 	mov[ 	]+0x0,%eax
 1c9:	8b 80 00 00 00 00[ 	]+mov[ 	]+0x0\(%rax\),%eax
 1cf:	8b 05 00 00 00 00[ 	]+mov[ 	]+0\(%rip\),%eax.*
 1d5:	b0 00[ 	]+mov[ 	]+\$0x0,%al
 1d7:	66 b8 00 00[ 	]+mov[ 	]+\$0x0,%ax
 1db:	b8 00 00 00 00[ 	]+mov[ 	]+\$0x0,%eax
 1e0:	48 c7 c0 00 00 00 00 	mov[ 	]+\$0x0,%rax
 1e7:	a1 00 00 00 00 00 00 00 00 	mov[ 	]+0x0,%eax
 1f0:	8b 04 25 00 00 00 00 	mov[ 	]+0x0,%eax
 1f7:	8b 80 00 00 00 00[ 	]+mov[ 	]+0x0\(%rax\),%eax
 1fd:	8b 05 00 00 00 00[ 	]+mov[ 	]+0\(%rip\),%eax.*

0+203 <foo>:
 203:	a0 11 22 33 44 55 66 77 88 	mov[ 	]+0x8877665544332211,%al
 20c:	66 a1 11 22 33 44 55 66 77 88 	mov[ 	]+0x8877665544332211,%ax
 216:	a1 11 22 33 44 55 66 77 88 	mov[ 	]+0x8877665544332211,%eax
 21f:	48 a1 11 22 33 44 55 66 77 88 	mov[ 	]+0x8877665544332211,%rax
 229:	a2 11 22 33 44 55 66 77 88 	mov[ 	]+%al,0x8877665544332211
 232:	66 a3 11 22 33 44 55 66 77 88 	mov[ 	]+%ax,0x8877665544332211
 23c:	a3 11 22 33 44 55 66 77 88 	mov[ 	]+%eax,0x8877665544332211
 245:	48 a3 11 22 33 44 55 66 77 88 	mov[ 	]+%rax,0x8877665544332211
 24f:	a0 11 22 33 44 55 66 77 88 	mov[ 	]+0x8877665544332211,%al
 258:	66 a1 11 22 33 44 55 66 77 88 	mov[ 	]+0x8877665544332211,%ax
 262:	a1 11 22 33 44 55 66 77 88 	mov[ 	]+0x8877665544332211,%eax
 26b:	48 a1 11 22 33 44 55 66 77 88 	mov[ 	]+0x8877665544332211,%rax
 275:	a2 11 22 33 44 55 66 77 88 	mov[ 	]+%al,0x8877665544332211
 27e:	66 a3 11 22 33 44 55 66 77 88 	mov[ 	]+%ax,0x8877665544332211
 288:	a3 11 22 33 44 55 66 77 88 	mov[ 	]+%eax,0x8877665544332211
 291:	48 a3 11 22 33 44 55 66 77 88 	mov[ 	]+%rax,0x8877665544332211
 29b:	8a 04 25 11 22 33 ff 	mov[ 	]+0xffffffffff332211,%al
 2a2:	66 8b 04 25 11 22 33 ff 	mov[ 	]+0xffffffffff332211,%ax
 2aa:	8b 04 25 11 22 33 ff 	mov[ 	]+0xffffffffff332211,%eax
 2b1:	48 8b 04 25 11 22 33 ff 	mov[ 	]+0xffffffffff332211,%rax
 2b9:	88 04 25 11 22 33 ff 	mov[ 	]+%al,0xffffffffff332211
 2c0:	66 89 04 25 11 22 33 ff 	mov[ 	]+%ax,0xffffffffff332211
 2c8:	89 04 25 11 22 33 ff 	mov[ 	]+%eax,0xffffffffff332211
 2cf:	48 89 04 25 11 22 33 ff 	mov[ 	]+%rax,0xffffffffff332211
 2d7:	8a 04 25 11 22 33 ff 	mov[ 	]+0xffffffffff332211,%al
 2de:	66 8b 04 25 11 22 33 ff 	mov[ 	]+0xffffffffff332211,%ax
 2e6:	8b 04 25 11 22 33 ff 	mov[ 	]+0xffffffffff332211,%eax
 2ed:	48 8b 04 25 11 22 33 ff 	mov[ 	]+0xffffffffff332211,%rax
 2f5:	88 04 25 11 22 33 ff 	mov[ 	]+%al,0xffffffffff332211
 2fc:	66 89 04 25 11 22 33 ff 	mov[ 	]+%ax,0xffffffffff332211
 304:	89 04 25 11 22 33 ff 	mov[ 	]+%eax,0xffffffffff332211
 30b:	48 89 04 25 11 22 33 ff 	mov[ 	]+%rax,0xffffffffff332211
#pass
