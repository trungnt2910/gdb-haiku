#objdump: -dr --prefix-addresses -mmips:3000
#name: MIPS ulh
#as: -mips1

# Test the ulh macro.

.*: +file format .*mips.*

Disassembly of section .text:
0+0000 <[^>]*> lb	at,[01]\(zero\)
0+0004 <[^>]*> lbu	a0,[01]\(zero\)
0+0008 <[^>]*> sll	at,at,0x8
0+000c <[^>]*> or	a0,a0,at
0+0010 <[^>]*> lb	at,[12]\(zero\)
0+0014 <[^>]*> lbu	a0,[12]\(zero\)
0+0018 <[^>]*> sll	at,at,0x8
0+001c <[^>]*> or	a0,a0,at
0+0020 <[^>]*> li	at,0x8000
0+0024 <[^>]*> lb	a0,[01]\(at\)
0+0028 <[^>]*> lbu	at,[01]\(at\)
0+002c <[^>]*> sll	a0,a0,0x8
0+0030 <[^>]*> or	a0,a0,at
0+0034 <[^>]*> lb	at,-3276[78]\(zero\)
0+0038 <[^>]*> lbu	a0,-3276[78]\(zero\)
0+003c <[^>]*> sll	at,at,0x8
0+0040 <[^>]*> or	a0,a0,at
0+0044 <[^>]*> lui	at,0x1
0+0048 <[^>]*> lb	a0,[01]\(at\)
0+004c <[^>]*> lbu	at,[01]\(at\)
0+0050 <[^>]*> sll	a0,a0,0x8
0+0054 <[^>]*> or	a0,a0,at
0+0058 <[^>]*> lui	at,0x1
0+005c <[^>]*> ori	at,at,0xa5a5
0+0060 <[^>]*> lb	a0,[01]\(at\)
0+0064 <[^>]*> lbu	at,[01]\(at\)
0+0068 <[^>]*> sll	a0,a0,0x8
0+006c <[^>]*> or	a0,a0,at
0+0070 <[^>]*> lb	at,[01]\(a1\)
0+0074 <[^>]*> lbu	a0,[01]\(a1\)
0+0078 <[^>]*> sll	at,at,0x8
0+007c <[^>]*> or	a0,a0,at
0+0080 <[^>]*> lb	at,[12]\(a1\)
0+0084 <[^>]*> lbu	a0,[12]\(a1\)
0+0088 <[^>]*> sll	at,at,0x8
0+008c <[^>]*> or	a0,a0,at
0+0090 <[^>]*> lui	at,[-0-9x]+
[ 	]*90: [A-Z0-9_]*HI[A-Z0-9_]*	.data.*
0+0094 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*94: [A-Z0-9_]*LO[A-Z0-9_]*	.data.*
0+0098 <[^>]*> lb	a0,[01]\(at\)
0+009c <[^>]*> lbu	at,[01]\(at\)
0+00a0 <[^>]*> sll	a0,a0,0x8
0+00a4 <[^>]*> or	a0,a0,at
0+00a8 <[^>]*> lui	at,0x0
[ 	]*a8: [A-Z0-9_]*HI[A-Z0-9_]*	big_external_data_label
0+00ac <[^>]*> addiu	at,at,[-0-9]+
[ 	]*ac: [A-Z0-9_]*LO[A-Z0-9_]*	big_external_data_label
0+00b0 <[^>]*> lb	a0,[01]\(at\)
0+00b4 <[^>]*> lbu	at,[01]\(at\)
0+00b8 <[^>]*> sll	a0,a0,0x8
0+00bc <[^>]*> or	a0,a0,at
0+00c0 <[^>]*> addiu	at,gp,0
[ 	]*c0: [A-Z0-9_]*GPREL[A-Z0-9_]*	small_external_data_label
0+00c4 <[^>]*> lb	a0,[01]\(at\)
0+00c8 <[^>]*> lbu	at,[01]\(at\)
0+00cc <[^>]*> sll	a0,a0,0x8
0+00d0 <[^>]*> or	a0,a0,at
0+00d4 <[^>]*> lui	at,0x0
[ 	]*d4: [A-Z0-9_]*HI[A-Z0-9_]*	big_external_common
0+00d8 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*d8: [A-Z0-9_]*LO[A-Z0-9_]*	big_external_common
0+00dc <[^>]*> lb	a0,[01]\(at\)
0+00e0 <[^>]*> lbu	at,[01]\(at\)
0+00e4 <[^>]*> sll	a0,a0,0x8
0+00e8 <[^>]*> or	a0,a0,at
0+00ec <[^>]*> addiu	at,gp,0
[ 	]*ec: [A-Z0-9_]*GPREL[A-Z0-9_]*	small_external_common
0+00f0 <[^>]*> lb	a0,[01]\(at\)
0+00f4 <[^>]*> lbu	at,[01]\(at\)
0+00f8 <[^>]*> sll	a0,a0,0x8
0+00fc <[^>]*> or	a0,a0,at
0+0100 <[^>]*> lui	at,[-0-9x]+
[ 	]*100: [A-Z0-9_]*HI[A-Z0-9_]*	.bss.*
0+0104 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*104: [A-Z0-9_]*LO[A-Z0-9_]*	.bss.*
0+0108 <[^>]*> lb	a0,[01]\(at\)
0+010c <[^>]*> lbu	at,[01]\(at\)
0+0110 <[^>]*> sll	a0,a0,0x8
0+0114 <[^>]*> or	a0,a0,at
0+0118 <[^>]*> addiu	at,gp,[-0-9]+
[ 	]*118: [A-Z0-9_]*GPREL[A-Z0-9_]*	.sbss.*
0+011c <[^>]*> lb	a0,[01]\(at\)
0+0120 <[^>]*> lbu	at,[01]\(at\)
0+0124 <[^>]*> sll	a0,a0,0x8
0+0128 <[^>]*> or	a0,a0,at
0+012c <[^>]*> lui	at,0x0
[ 	]*12c: [A-Z0-9_]*HI[A-Z0-9_]*	.data.*
0+0130 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*130: [A-Z0-9_]*LO[A-Z0-9_]*	.data.*
0+0134 <[^>]*> lb	a0,[01]\(at\)
0+0138 <[^>]*> lbu	at,[01]\(at\)
0+013c <[^>]*> sll	a0,a0,0x8
0+0140 <[^>]*> or	a0,a0,at
0+0144 <[^>]*> lui	at,0x0
[ 	]*144: [A-Z0-9_]*HI[A-Z0-9_]*	big_external_data_label
0+0148 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*148: [A-Z0-9_]*LO[A-Z0-9_]*	big_external_data_label
0+014c <[^>]*> lb	a0,[01]\(at\)
0+0150 <[^>]*> lbu	at,[01]\(at\)
0+0154 <[^>]*> sll	a0,a0,0x8
0+0158 <[^>]*> or	a0,a0,at
0+015c <[^>]*> addiu	at,gp,1
[ 	]*15c: [A-Z0-9_]*GPREL[A-Z0-9_]*	small_external_data_label
0+0160 <[^>]*> lb	a0,[01]\(at\)
0+0164 <[^>]*> lbu	at,[01]\(at\)
0+0168 <[^>]*> sll	a0,a0,0x8
0+016c <[^>]*> or	a0,a0,at
0+0170 <[^>]*> lui	at,0x0
[ 	]*170: [A-Z0-9_]*HI[A-Z0-9_]*	big_external_common
0+0174 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*174: [A-Z0-9_]*LO[A-Z0-9_]*	big_external_common
0+0178 <[^>]*> lb	a0,[01]\(at\)
0+017c <[^>]*> lbu	at,[01]\(at\)
0+0180 <[^>]*> sll	a0,a0,0x8
0+0184 <[^>]*> or	a0,a0,at
0+0188 <[^>]*> addiu	at,gp,1
[ 	]*188: [A-Z0-9_]*GPREL[A-Z0-9_]*	small_external_common
0+018c <[^>]*> lb	a0,[01]\(at\)
0+0190 <[^>]*> lbu	at,[01]\(at\)
0+0194 <[^>]*> sll	a0,a0,0x8
0+0198 <[^>]*> or	a0,a0,at
0+019c <[^>]*> lui	at,0x0
[ 	]*19c: [A-Z0-9_]*HI[A-Z0-9_]*	.bss.*
0+01a0 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*1a0: [A-Z0-9_]*LO[A-Z0-9_]*	.bss.*
0+01a4 <[^>]*> lb	a0,[01]\(at\)
0+01a8 <[^>]*> lbu	at,[01]\(at\)
0+01ac <[^>]*> sll	a0,a0,0x8
0+01b0 <[^>]*> or	a0,a0,at
0+01b4 <[^>]*> addiu	at,gp,[-0-9]+
[ 	]*1b4: [A-Z0-9_]*GPREL[A-Z0-9_]*	.sbss.*
0+01b8 <[^>]*> lb	a0,[01]\(at\)
0+01bc <[^>]*> lbu	at,[01]\(at\)
0+01c0 <[^>]*> sll	a0,a0,0x8
0+01c4 <[^>]*> or	a0,a0,at
0+01c8 <[^>]*> lui	at,[-0-9x]+
[ 	]*1c8: [A-Z0-9_]*HI[A-Z0-9_]*	.data.*
0+01cc <[^>]*> addiu	at,at,[-0-9]+
[ 	]*1cc: [A-Z0-9_]*LO[A-Z0-9_]*	.data.*
0+01d0 <[^>]*> lb	a0,[01]\(at\)
0+01d4 <[^>]*> lbu	at,[01]\(at\)
0+01d8 <[^>]*> sll	a0,a0,0x8
0+01dc <[^>]*> or	a0,a0,at
0+01e0 <[^>]*> lui	at,[-0-9x]+
[ 	]*1e0: [A-Z0-9_]*HI[A-Z0-9_]*	big_external_data_label
0+01e4 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*1e4: [A-Z0-9_]*LO[A-Z0-9_]*	big_external_data_label
0+01e8 <[^>]*> lb	a0,[01]\(at\)
0+01ec <[^>]*> lbu	at,[01]\(at\)
0+01f0 <[^>]*> sll	a0,a0,0x8
0+01f4 <[^>]*> or	a0,a0,at
0+01f8 <[^>]*> lui	at,[-0-9x]+
[ 	]*1f8: [A-Z0-9_]*HI[A-Z0-9_]*	small_external_data_label
0+01fc <[^>]*> addiu	at,at,[-0-9]+
[ 	]*1fc: [A-Z0-9_]*LO[A-Z0-9_]*	small_external_data_label
0+0200 <[^>]*> lb	a0,[01]\(at\)
0+0204 <[^>]*> lbu	at,[01]\(at\)
0+0208 <[^>]*> sll	a0,a0,0x8
0+020c <[^>]*> or	a0,a0,at
0+0210 <[^>]*> lui	at,[-0-9x]+
[ 	]*210: [A-Z0-9_]*HI[A-Z0-9_]*	big_external_common
0+0214 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*214: [A-Z0-9_]*LO[A-Z0-9_]*	big_external_common
0+0218 <[^>]*> lb	a0,[01]\(at\)
0+021c <[^>]*> lbu	at,[01]\(at\)
0+0220 <[^>]*> sll	a0,a0,0x8
0+0224 <[^>]*> or	a0,a0,at
0+0228 <[^>]*> lui	at,[-0-9x]+
[ 	]*228: [A-Z0-9_]*HI[A-Z0-9_]*	small_external_common
0+022c <[^>]*> addiu	at,at,[-0-9]+
[ 	]*22c: [A-Z0-9_]*LO[A-Z0-9_]*	small_external_common
0+0230 <[^>]*> lb	a0,[01]\(at\)
0+0234 <[^>]*> lbu	at,[01]\(at\)
0+0238 <[^>]*> sll	a0,a0,0x8
0+023c <[^>]*> or	a0,a0,at
0+0240 <[^>]*> lui	at,[-0-9x]+
[ 	]*240: [A-Z0-9_]*HI[A-Z0-9_]*	.bss.*
0+0244 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*244: [A-Z0-9_]*LO[A-Z0-9_]*	.bss.*
0+0248 <[^>]*> lb	a0,[01]\(at\)
0+024c <[^>]*> lbu	at,[01]\(at\)
0+0250 <[^>]*> sll	a0,a0,0x8
0+0254 <[^>]*> or	a0,a0,at
0+0258 <[^>]*> lui	at,[-0-9x]+
[ 	]*258: [A-Z0-9_]*HI[A-Z0-9_]*	.sbss.*
0+025c <[^>]*> addiu	at,at,[-0-9]+
[ 	]*25c: [A-Z0-9_]*LO[A-Z0-9_]*	.sbss.*
0+0260 <[^>]*> lb	a0,[01]\(at\)
0+0264 <[^>]*> lbu	at,[01]\(at\)
0+0268 <[^>]*> sll	a0,a0,0x8
0+026c <[^>]*> or	a0,a0,at
0+0270 <[^>]*> lui	at,0x0
[ 	]*270: [A-Z0-9_]*HI[A-Z0-9_]*	.data.*
0+0274 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*274: [A-Z0-9_]*LO[A-Z0-9_]*	.data.*
0+0278 <[^>]*> lb	a0,[01]\(at\)
0+027c <[^>]*> lbu	at,[01]\(at\)
0+0280 <[^>]*> sll	a0,a0,0x8
0+0284 <[^>]*> or	a0,a0,at
0+0288 <[^>]*> lui	at,0x0
[ 	]*288: [A-Z0-9_]*HI[A-Z0-9_]*	big_external_data_label
0+028c <[^>]*> addiu	at,at,[-0-9]+
[ 	]*28c: [A-Z0-9_]*LO[A-Z0-9_]*	big_external_data_label
0+0290 <[^>]*> lb	a0,[01]\(at\)
0+0294 <[^>]*> lbu	at,[01]\(at\)
0+0298 <[^>]*> sll	a0,a0,0x8
0+029c <[^>]*> or	a0,a0,at
0+02a0 <[^>]*> lui	at,0x0
[ 	]*2a0: [A-Z0-9_]*HI[A-Z0-9_]*	small_external_data_label
0+02a4 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*2a4: [A-Z0-9_]*LO[A-Z0-9_]*	small_external_data_label
0+02a8 <[^>]*> lb	a0,[01]\(at\)
0+02ac <[^>]*> lbu	at,[01]\(at\)
0+02b0 <[^>]*> sll	a0,a0,0x8
0+02b4 <[^>]*> or	a0,a0,at
0+02b8 <[^>]*> lui	at,0x0
[ 	]*2b8: [A-Z0-9_]*HI[A-Z0-9_]*	big_external_common
0+02bc <[^>]*> addiu	at,at,[-0-9]+
[ 	]*2bc: [A-Z0-9_]*LO[A-Z0-9_]*	big_external_common
0+02c0 <[^>]*> lb	a0,[01]\(at\)
0+02c4 <[^>]*> lbu	at,[01]\(at\)
0+02c8 <[^>]*> sll	a0,a0,0x8
0+02cc <[^>]*> or	a0,a0,at
0+02d0 <[^>]*> lui	at,0x0
[ 	]*2d0: [A-Z0-9_]*HI[A-Z0-9_]*	small_external_common
0+02d4 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*2d4: [A-Z0-9_]*LO[A-Z0-9_]*	small_external_common
0+02d8 <[^>]*> lb	a0,[01]\(at\)
0+02dc <[^>]*> lbu	at,[01]\(at\)
0+02e0 <[^>]*> sll	a0,a0,0x8
0+02e4 <[^>]*> or	a0,a0,at
0+02e8 <[^>]*> lui	at,0x0
[ 	]*2e8: [A-Z0-9_]*HI[A-Z0-9_]*	.bss.*
0+02ec <[^>]*> addiu	at,at,[-0-9]+
[ 	]*2ec: [A-Z0-9_]*LO[A-Z0-9_]*	.bss.*
0+02f0 <[^>]*> lb	a0,[01]\(at\)
0+02f4 <[^>]*> lbu	at,[01]\(at\)
0+02f8 <[^>]*> sll	a0,a0,0x8
0+02fc <[^>]*> or	a0,a0,at
0+0300 <[^>]*> lui	at,0x0
[ 	]*300: [A-Z0-9_]*HI[A-Z0-9_]*	.sbss.*
0+0304 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*304: [A-Z0-9_]*LO[A-Z0-9_]*	.sbss.*
0+0308 <[^>]*> lb	a0,[01]\(at\)
0+030c <[^>]*> lbu	at,[01]\(at\)
0+0310 <[^>]*> sll	a0,a0,0x8
0+0314 <[^>]*> or	a0,a0,at
0+0318 <[^>]*> lui	at,[-0-9x]+
[ 	]*318: [A-Z0-9_]*HI[A-Z0-9_]*	.data.*
0+031c <[^>]*> addiu	at,at,[-0-9]+
[ 	]*31c: [A-Z0-9_]*LO[A-Z0-9_]*	.data.*
0+0320 <[^>]*> lb	a0,[01]\(at\)
0+0324 <[^>]*> lbu	at,[01]\(at\)
0+0328 <[^>]*> sll	a0,a0,0x8
0+032c <[^>]*> or	a0,a0,at
0+0330 <[^>]*> lui	at,[-0-9x]+
[ 	]*330: [A-Z0-9_]*HI[A-Z0-9_]*	big_external_data_label
0+0334 <[^>]*> addiu	at,at,0
[ 	]*334: [A-Z0-9_]*LO[A-Z0-9_]*	big_external_data_label
0+0338 <[^>]*> lb	a0,[01]\(at\)
0+033c <[^>]*> lbu	at,[01]\(at\)
0+0340 <[^>]*> sll	a0,a0,0x8
0+0344 <[^>]*> or	a0,a0,at
0+0348 <[^>]*> lui	at,[-0-9x]+
[ 	]*348: [A-Z0-9_]*HI[A-Z0-9_]*	small_external_data_label
0+034c <[^>]*> addiu	at,at,0
[ 	]*34c: [A-Z0-9_]*LO[A-Z0-9_]*	small_external_data_label
0+0350 <[^>]*> lb	a0,[01]\(at\)
0+0354 <[^>]*> lbu	at,[01]\(at\)
0+0358 <[^>]*> sll	a0,a0,0x8
0+035c <[^>]*> or	a0,a0,at
0+0360 <[^>]*> lui	at,[-0-9x]+
[ 	]*360: [A-Z0-9_]*HI[A-Z0-9_]*	big_external_common
0+0364 <[^>]*> addiu	at,at,0
[ 	]*364: [A-Z0-9_]*LO[A-Z0-9_]*	big_external_common
0+0368 <[^>]*> lb	a0,[01]\(at\)
0+036c <[^>]*> lbu	at,[01]\(at\)
0+0370 <[^>]*> sll	a0,a0,0x8
0+0374 <[^>]*> or	a0,a0,at
0+0378 <[^>]*> lui	at,[-0-9x]+
[ 	]*378: [A-Z0-9_]*HI[A-Z0-9_]*	small_external_common
0+037c <[^>]*> addiu	at,at,0
[ 	]*37c: [A-Z0-9_]*LO[A-Z0-9_]*	small_external_common
0+0380 <[^>]*> lb	a0,[01]\(at\)
0+0384 <[^>]*> lbu	at,[01]\(at\)
0+0388 <[^>]*> sll	a0,a0,0x8
0+038c <[^>]*> or	a0,a0,at
0+0390 <[^>]*> lui	at,[-0-9x]+
[ 	]*390: [A-Z0-9_]*HI[A-Z0-9_]*	.bss.*
0+0394 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*394: [A-Z0-9_]*LO[A-Z0-9_]*	.bss.*
0+0398 <[^>]*> lb	a0,[01]\(at\)
0+039c <[^>]*> lbu	at,[01]\(at\)
0+03a0 <[^>]*> sll	a0,a0,0x8
0+03a4 <[^>]*> or	a0,a0,at
0+03a8 <[^>]*> lui	at,[-0-9x]+
[ 	]*3a8: [A-Z0-9_]*HI[A-Z0-9_]*	.sbss.*
0+03ac <[^>]*> addiu	at,at,[-0-9]+
[ 	]*3ac: [A-Z0-9_]*LO[A-Z0-9_]*	.sbss.*
0+03b0 <[^>]*> lb	a0,[01]\(at\)
0+03b4 <[^>]*> lbu	at,[01]\(at\)
0+03b8 <[^>]*> sll	a0,a0,0x8
0+03bc <[^>]*> or	a0,a0,at
0+03c0 <[^>]*> lui	at,[-0-9x]+
[ 	]*3c0: [A-Z0-9_]*HI[A-Z0-9_]*	.data.*
0+03c4 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*3c4: [A-Z0-9_]*LO[A-Z0-9_]*	.data.*
0+03c8 <[^>]*> lb	a0,[01]\(at\)
0+03cc <[^>]*> lbu	at,[01]\(at\)
0+03d0 <[^>]*> sll	a0,a0,0x8
0+03d4 <[^>]*> or	a0,a0,at
0+03d8 <[^>]*> lui	at,[-0-9x]+
[ 	]*3d8: [A-Z0-9_]*HI[A-Z0-9_]*	big_external_data_label
0+03dc <[^>]*> addiu	at,at,[-0-9]+
[ 	]*3dc: [A-Z0-9_]*LO[A-Z0-9_]*	big_external_data_label
0+03e0 <[^>]*> lb	a0,[01]\(at\)
0+03e4 <[^>]*> lbu	at,[01]\(at\)
0+03e8 <[^>]*> sll	a0,a0,0x8
0+03ec <[^>]*> or	a0,a0,at
0+03f0 <[^>]*> lui	at,[-0-9x]+
[ 	]*3f0: [A-Z0-9_]*HI[A-Z0-9_]*	small_external_data_label
0+03f4 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*3f4: [A-Z0-9_]*LO[A-Z0-9_]*	small_external_data_label
0+03f8 <[^>]*> lb	a0,[01]\(at\)
0+03fc <[^>]*> lbu	at,[01]\(at\)
0+0400 <[^>]*> sll	a0,a0,0x8
0+0404 <[^>]*> or	a0,a0,at
0+0408 <[^>]*> lui	at,[-0-9x]+
[ 	]*408: [A-Z0-9_]*HI[A-Z0-9_]*	big_external_common
0+040c <[^>]*> addiu	at,at,[-0-9]+
[ 	]*40c: [A-Z0-9_]*LO[A-Z0-9_]*	big_external_common
0+0410 <[^>]*> lb	a0,[01]\(at\)
0+0414 <[^>]*> lbu	at,[01]\(at\)
0+0418 <[^>]*> sll	a0,a0,0x8
0+041c <[^>]*> or	a0,a0,at
0+0420 <[^>]*> lui	at,[-0-9x]+
[ 	]*420: [A-Z0-9_]*HI[A-Z0-9_]*	small_external_common
0+0424 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*424: [A-Z0-9_]*LO[A-Z0-9_]*	small_external_common
0+0428 <[^>]*> lb	a0,[01]\(at\)
0+042c <[^>]*> lbu	at,[01]\(at\)
0+0430 <[^>]*> sll	a0,a0,0x8
0+0434 <[^>]*> or	a0,a0,at
0+0438 <[^>]*> lui	at,[-0-9x]+
[ 	]*438: [A-Z0-9_]*HI[A-Z0-9_]*	.bss.*
0+043c <[^>]*> addiu	at,at,[-0-9]+
[ 	]*43c: [A-Z0-9_]*LO[A-Z0-9_]*	.bss.*
0+0440 <[^>]*> lb	a0,[01]\(at\)
0+0444 <[^>]*> lbu	at,[01]\(at\)
0+0448 <[^>]*> sll	a0,a0,0x8
0+044c <[^>]*> or	a0,a0,at
0+0450 <[^>]*> lui	at,[-0-9x]+
[ 	]*450: [A-Z0-9_]*HI[A-Z0-9_]*	.sbss.*
0+0454 <[^>]*> addiu	at,at,[-0-9]+
[ 	]*454: [A-Z0-9_]*LO[A-Z0-9_]*	.sbss.*
0+0458 <[^>]*> lb	a0,[01]\(at\)
0+045c <[^>]*> lbu	at,[01]\(at\)
0+0460 <[^>]*> sll	a0,a0,0x8
0+0464 <[^>]*> or	a0,a0,at
0+0468 <[^>]*> lbu	at,[01]\(zero\)
0+046c <[^>]*> lbu	a0,[01]\(zero\)
0+0470 <[^>]*> sll	at,at,0x8
0+0474 <[^>]*> or	a0,a0,at
	...
