
.*:     file format .*

Disassembly of section .text:

00001000 <_start>:
    1000:	eb000000 	bl	1008 <__bar_from_arm>
    1004:	eb000002 	bl	1014 <__bar2_veneer>

00001008 <__bar_from_arm>:
    1008:	e59fc000 	ldr	ip, \[pc, #0\]	; 1010 <__bar_from_arm\+0x8>
    100c:	e12fff1c 	bx	ip
    1010:	02003021 	.word	0x02003021
00001014 <__bar2_veneer>:
    1014:	e51ff004 	ldr	pc, \[pc, #-4\]	; 1018 <__bar2_veneer\+0x4>
    1018:	02003024 	.word	0x02003024
    101c:	00000000 	.word	0x00000000
Disassembly of section .mytext:

00002000 <__bar5_from_arm-0x10>:
    2000:	eb000008 	bl	2028 <__bar3_veneer>
    2004:	eb000004 	bl	201c <__bar4_from_arm>
    2008:	eb000000 	bl	2010 <__bar5_from_arm>
    200c:	00000000 	andeq	r0, r0, r0
00002010 <__bar5_from_arm>:
    2010:	e59fc000 	ldr	ip, \[pc, #0\]	; 2018 <__bar5_from_arm\+0x8>
    2014:	e12fff1c 	bx	ip
    2018:	0200302f 	.word	0x0200302f
0000201c <__bar4_from_arm>:
    201c:	e59fc000 	ldr	ip, \[pc, #0\]	; 2024 <__bar4_from_arm\+0x8>
    2020:	e12fff1c 	bx	ip
    2024:	0200302d 	.word	0x0200302d
00002028 <__bar3_veneer>:
    2028:	e51ff004 	ldr	pc, \[pc, #-4\]	; 202c <__bar3_veneer\+0x4>
    202c:	02003028 	.word	0x02003028
	...
Disassembly of section .foo:

02003020 <bar>:
 2003020:	4770      	bx	lr
	...

02003024 <bar2>:
 2003024:	e12fff1e 	bx	lr

02003028 <bar3>:
 2003028:	e12fff1e 	bx	lr

0200302c <bar4>:
 200302c:	4770      	bx	lr

0200302e <bar5>:
 200302e:	4770      	bx	lr
