#source: tlstoc.s
#as: -a64
#ld: -shared
#objdump: -dr
#target: powerpc64*-*-*

.*: +file format elf64-powerpc

Disassembly of section \.text:

.* <00000010\.plt_call\.__tls_get_addr(|_opt)\+0>:
.*	(f8 41 00 28|28 00 41 f8) 	std     r2,40\(r1\)
.*	(e9 62 80 70|70 80 62 e9) 	ld      r11,-32656\(r2\)
.*	(7d 69 03 a6|a6 03 69 7d) 	mtctr   r11
.*	(e8 42 80 78|78 80 42 e8) 	ld      r2,-32648\(r2\)
.*	(4e 80 04 20|20 04 80 4e) 	bctr

.* <_start>:
.*	(38 62 80 08|08 80 62 38) 	addi    r3,r2,-32760
.*	(4b ff ff e9|e9 ff ff 4b) 	bl      .*
.*	(e8 41 00 28|28 00 41 e8) 	ld      r2,40\(r1\)
.*	(38 62 80 18|18 80 62 38) 	addi    r3,r2,-32744
.*	(4b ff ff dd|dd ff ff 4b) 	bl      .*
.*	(e8 41 00 28|28 00 41 e8) 	ld      r2,40\(r1\)
.*	(38 62 80 28|28 80 62 38) 	addi    r3,r2,-32728
.*	(4b ff ff d1|d1 ff ff 4b) 	bl      .*
.*	(e8 41 00 28|28 00 41 e8) 	ld      r2,40\(r1\)
.*	(38 62 80 38|38 80 62 38) 	addi    r3,r2,-32712
.*	(4b ff ff c5|c5 ff ff 4b) 	bl      .*
.*	(e8 41 00 28|28 00 41 e8) 	ld      r2,40\(r1\)
.*	(39 23 80 40|40 80 23 39) 	addi    r9,r3,-32704
.*	(3d 23 00 00|00 00 23 3d) 	addis   r9,r3,0
.*	(81 49 80 48|48 80 49 81) 	lwz     r10,-32696\(r9\)
.*	(e9 22 80 48|48 80 22 e9) 	ld      r9,-32696\(r2\)
.*	(7d 49 18 2a|2a 18 49 7d) 	ldx     r10,r9,r3
.*	(e9 22 80 50|50 80 22 e9) 	ld      r9,-32688\(r2\)
.*	(7d 49 6a 2e|2e 6a 49 7d) 	lhzx    r10,r9,r13
.*	(89 4d 00 00|00 00 4d 89) 	lbz     r10,0\(r13\)
.*	(3d 2d 00 00|00 00 2d 3d) 	addis   r9,r13,0
.*	(99 49 00 00|00 00 49 99) 	stb     r10,0\(r9\)
.*	(60 00 00 00|00 00 00 60) 	nop
.*	(00 00 00 00|18 02 01 00) .*
.*	(00 01 02 18|00 00 00 00) .*
.* <__glink_PLTresolve>:
.*	(7d 88 02 a6|a6 02 88 7d) 	mflr    r12
.*	(42 9f 00 05|05 00 9f 42) 	bcl-    20,4\*cr7\+so,.*
.*	(7d 68 02 a6|a6 02 68 7d) 	mflr    r11
.*	(e8 4b ff f0|f0 ff 4b e8) 	ld      r2,-16\(r11\)
.*	(7d 88 03 a6|a6 03 88 7d) 	mtlr    r12
.*	(7d 82 5a 14|14 5a 82 7d) 	add     r12,r2,r11
.*	(e9 6c 00 00|00 00 6c e9) 	ld      r11,0\(r12\)
.*	(e8 4c 00 08|08 00 4c e8) 	ld      r2,8\(r12\)
.*	(7d 69 03 a6|a6 03 69 7d) 	mtctr   r11
.*	(e9 6c 00 10|10 00 6c e9) 	ld      r11,16\(r12\)
.*	(4e 80 04 20|20 04 80 4e) 	bctr
.*	(60 00 00 00|00 00 00 60) 	nop
.*	(60 00 00 00|00 00 00 60) 	nop
.*	(60 00 00 00|00 00 00 60) 	nop
.*	(38 00 00 00|00 00 00 38) 	li      r0,0
.*	(4b ff ff c4|c4 ff ff 4b) 	b       .*
