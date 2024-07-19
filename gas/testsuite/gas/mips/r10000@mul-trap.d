#as: -32 -trap
#objdump: -dr --prefix-addresses --show-raw-insn
#name: MIPS mul with traps
#source: mul.s

# Test the mul macro.

.*: +file format .*mips.*

Disassembly of section \.text:
[0-9a-f]+ <[^>]*> 00850019 	multu	a0,a1
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 00a60019 	multu	a1,a2
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 24010000 	li	at,0
[0-9a-f]+ <[^>]*> 00a10018 	mult	a1,at
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 24010001 	li	at,1
[0-9a-f]+ <[^>]*> 00a10018 	mult	a1,at
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 34018000 	li	at,0x8000
[0-9a-f]+ <[^>]*> 00a10018 	mult	a1,at
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 24018000 	li	at,-32768
[0-9a-f]+ <[^>]*> 00a10018 	mult	a1,at
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 3c010001 	lui	at,0x1
[0-9a-f]+ <[^>]*> 00a10018 	mult	a1,at
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 3c010001 	lui	at,0x1
[0-9a-f]+ <[^>]*> 3421a5a5 	ori	at,at,0xa5a5
[0-9a-f]+ <[^>]*> 00a10018 	mult	a1,at
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 00850018 	mult	a0,a1
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 000427c3 	sra	a0,a0,0x1f
[0-9a-f]+ <[^>]*> 00000810 	mfhi	at
[0-9a-f]+ <[^>]*> 008101b6 	tne	a0,at,0x6
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 00a60018 	mult	a1,a2
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 000427c3 	sra	a0,a0,0x1f
[0-9a-f]+ <[^>]*> 00000810 	mfhi	at
[0-9a-f]+ <[^>]*> 008101b6 	tne	a0,at,0x6
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 00850019 	multu	a0,a1
[0-9a-f]+ <[^>]*> 00000810 	mfhi	at
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 002001b6 	tne	at,zero,0x6
[0-9a-f]+ <[^>]*> 00a60019 	multu	a1,a2
[0-9a-f]+ <[^>]*> 00000810 	mfhi	at
[0-9a-f]+ <[^>]*> 00002012 	mflo	a0
[0-9a-f]+ <[^>]*> 002001b6 	tne	at,zero,0x6
	\.\.\.
