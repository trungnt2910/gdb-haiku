#source: tlsmark32.s
#source: tlslib32.s
#as: -a32
#ld: 
#objdump: -dr
#target: powerpc*-*-*

.*

Disassembly of section \.text:

0+1800094 <_start>:
.*:	(48 00 00 14|14 00 00 48) 	b       18000a8 <_start\+0x14>
.*:	(38 63 90 00|00 90 63 38) 	addi    r3,r3,-28672
.*:	(80 83 00 00|00 00 83 80) 	lwz     r4,0\(r3\)
.*:	(3c 62 00 00|00 00 62 3c) 	addis   r3,r2,0
.*:	(48 00 00 0c|0c 00 00 48) 	b       18000b0 <_start\+0x1c>
.*:	(3c 62 00 00|00 00 62 3c) 	addis   r3,r2,0
.*:	(4b ff ff ec|ec ff ff 4b) 	b       1800098 <_start\+0x4>
.*:	(38 63 10 00|00 10 63 38) 	addi    r3,r3,4096
.*:	(80 83 80 00|00 80 83 80) 	lwz     r4,-32768\(r3\)

0+18000b8 <__tls_get_addr>:
.*:	(4e 80 00 20|20 00 80 4e) 	blr
#pass