#objdump: -dr --prefix-addresses --show-raw-insn
#name: MIPS16 PC-relative relocation 5
#as: -32 -mips3

.*: +file format .*mips.*

Disassembly of section \.text:
	\.\.\.
	\.\.\.
[0-9a-f]+ <[^>]*> f7ff fe40 	dla	v0,00001000 <bar>
[0-9a-f]+ <[^>]*> f7ff fc40 	ld	v0,00001000 <bar>
[0-9a-f]+ <[^>]*> 6500      	nop
	\.\.\.
