#source: adj-brset.s
#as: -m68hc11
#ld: -m m68hc11elf --relax
#objdump: -d --prefix-addresses -r

.*: +file format elf32\-m68hc11

Disassembly of section .text:
0+8000 <_start> brclr	0x8c,x, #0xc8, 0x0+804a <L8>
0+8004 <L1> addd	\*0x0+4 <_toto>
0+8006 <L1\+0x2> brclr	0x14,x, \#0x03, 0x0+8004 <L1>
0+800a <L1\+0x6> brclr	0x5a,x, \#0x63, 0x0+801a <L3>
0+800e <L2> addd	\*0x0+4 <_toto>
0+8010 <L2\+0x2> brclr	0x13,y, \#0x04, 0x0+800e <L2>
0+8015 <L2\+0x7> brclr	0x5b,y, \#0x62, 0x0+8024 <L4>
0+801a <L3> addd	\*0x0+4 <_toto>
0+801c <L3\+0x2> brset	0x12,x, \#0x05, 0x0+801a <L3>
0+8020 <L3\+0x6> brset	0x5c,x, \#0x61, 0x0+8030 <L5>
0+8024 <L4> addd	\*0x0+4 <_toto>
0+8026 <L4\+0x2> brset	0x11,y, \#0x06, 0x0+8024 <L4>
0+802b <L4\+0x7> brset	0x5d,y, \#0x60, 0x0+8030 <L5>
0+8030 <L5> addd	\*0x0+4 <_toto>
0+8032 <L5\+0x2> brset	\*0x0+32 <_table>, \#0x07, 0x0+8030 <L5>
0+8036 <L5\+0x6> brset	\*0x0+3c <_table\+0xa>, \#0x5f, 0x0+8044 <L7>
0+803a <L6> addd	\*0x0+4 <_toto>
0+803c <L6\+0x2> brclr	\*0x0+33 <_table\+0x1>, \#0x08, 0x0+803a <L6>
0+8040 <L6\+0x6> brset	\*0x0+3d <_table\+0xb>, \#0x5e, 0x0+804a <L8>
0+8044 <L7> addd	\*0x0+4 <_toto>
0+8046 <L7\+0x2> brclr	\*0x0+33 <_table\+0x1>, \#0x08, 0x0+803a <L6>
0+804a <L8> brclr	0x8c,x, \#0xc8, 0x0+8000 <_start>
0+804e <L8\+0x4> rts
