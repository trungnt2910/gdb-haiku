#objdump: -dr
#as: -mfix-24k -32
#name: 24K: Triple Store (Range Check)

.*: +file format .*mips.*

Disassembly of section .text:
00000000 <.text>:
   0:	a3a20000 	sb	v0,0\(sp\)
   4:	00000000 	nop
   8:	a3a3000a 	sb	v1,10\(sp\)
   c:	a3a4001f 	sb	a0,31\(sp\)
  10:	0000000d 	break
  14:	a7a20000 	sh	v0,0\(sp\)
  18:	a7a3fff0 	sh	v1,-16\(sp\)
  1c:	a7a4ffe0 	sh	a0,-32\(sp\)
  20:	0000000d 	break
  24:	afa20000 	sw	v0,0\(sp\)
  28:	afa3fff8 	sw	v1,-8\(sp\)
  2c:	00000000 	nop
  30:	afa40008 	sw	a0,8\(sp\)
  34:	0000000d 	break
  38:	bba20000 	swr	v0,0\(sp\)
  3c:	bba3fff0 	swr	v1,-16\(sp\)
  40:	bba40010 	swr	a0,16\(sp\)
  44:	0000000d 	break
  48:	aba20000 	swl	v0,0\(sp\)
  4c:	aba30008 	swl	v1,8\(sp\)
  50:	00000000 	nop
  54:	aba40010 	swl	a0,16\(sp\)
  58:	aba50018 	swl	a1,24\(sp\)
  5c:	00000000 	nop
  60:	aba60000 	swl	a2,0\(sp\)
  64:	0000000d 	break
  68:	e3a20020 	sc	v0,32\(sp\)
  6c:	e3a30008 	sc	v1,8\(sp\)
  70:	e3a4fff8 	sc	a0,-8\(sp\)
  74:	00000000 	nop
  78:	e3a50000 	sc	a1,0\(sp\)
  7c:	e3a60020 	sc	a2,32\(sp\)
	\.\.\.
