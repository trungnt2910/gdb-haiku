#objdump: -dr --prefix-addresses --show-raw-insn -M reg-names=32
#name: MIPS DSP ASE for MIPS64
#as: -mdsp -mips64r2

# Check MIPS DSP ASE for MIPS64 Instruction Assembly

.*: +file format .*mips.*

Disassembly of section .text:
0+0000 <[^>]*> 7c010456 	absq_s\.pw	zero,at
0+0004 <[^>]*> 7c1ff256 	absq_s\.qh	s8,ra
0+0008 <[^>]*> 7cc72c94 	addq\.pw	a1,a2,a3
0+000c <[^>]*> 7ce83594 	addq_s\.pw	a2,a3,t0
0+0010 <[^>]*> 7c641294 	addq\.qh	v0,v1,a0
0+0014 <[^>]*> 7c851b94 	addq_s\.qh	v1,a0,a1
0+0018 <[^>]*> 7d4b4814 	addu\.ob	t1,t2,t3
0+001c <[^>]*> 7d6c5114 	addu_s\.ob	t2,t3,t4
0+0020 <[^>]*> 041dfff7 	bposge64	00000000 <text_label>
0+0024 <[^>]*> 00000000 	nop
0+0028 <[^>]*> 7e950415 	cmp\.eq\.pw	s4,s5
0+002c <[^>]*> 7eb60455 	cmp\.lt\.pw	s5,s6
0+0030 <[^>]*> 7ed70495 	cmp\.le\.pw	s6,s7
0+0034 <[^>]*> 7e320215 	cmp\.eq\.qh	s1,s2
0+0038 <[^>]*> 7e530255 	cmp\.lt\.qh	s2,s3
0+003c <[^>]*> 7e740295 	cmp\.le\.qh	s3,s4
0+0040 <[^>]*> 7dcf0015 	cmpu\.eq\.ob	t6,t7
0+0044 <[^>]*> 7df00055 	cmpu\.lt\.ob	t7,s0
0+0048 <[^>]*> 7e110095 	cmpu\.le\.ob	s0,s1
0+004c <[^>]*> 7d2a4115 	cmpgu\.eq\.ob	t0,t1,t2
0+0050 <[^>]*> 7d4b4955 	cmpgu\.lt\.ob	t1,t2,t3
0+0054 <[^>]*> 7d6c5195 	cmpgu\.le\.ob	t2,t3,t4
0+0058 <[^>]*> 7c1f1abc 	dextpdp	ra,\$ac3,0x0
0+005c <[^>]*> 7c3f1abc 	dextpdp	ra,\$ac3,0x1
0+0060 <[^>]*> 7fff1abc 	dextpdp	ra,\$ac3,0x1f
0+0064 <[^>]*> 7c2002fc 	dextpdpv	zero,\$ac0,at
0+0068 <[^>]*> 7c1d08bc 	dextp	sp,\$ac1,0x0
0+006c <[^>]*> 7c3d08bc 	dextp	sp,\$ac1,0x1
0+0070 <[^>]*> 7ffd08bc 	dextp	sp,\$ac1,0x1f
0+0074 <[^>]*> 7ffe10fc 	dextpv	s8,\$ac2,ra
0+0078 <[^>]*> 7c031c3c 	dextr\.l	v1,\$ac3,0x0
0+007c <[^>]*> 7c231c3c 	dextr\.l	v1,\$ac3,0x1
0+0080 <[^>]*> 7fe31c3c 	dextr\.l	v1,\$ac3,0x1f
0+0084 <[^>]*> 7c04053c 	dextr_r\.l	a0,\$ac0,0x0
0+0088 <[^>]*> 7c24053c 	dextr_r\.l	a0,\$ac0,0x1
0+008c <[^>]*> 7fe4053c 	dextr_r\.l	a0,\$ac0,0x1f
0+0090 <[^>]*> 7c050dbc 	dextr_rs\.l	a1,\$ac1,0x0
0+0094 <[^>]*> 7c250dbc 	dextr_rs\.l	a1,\$ac1,0x1
0+0098 <[^>]*> 7fe50dbc 	dextr_rs\.l	a1,\$ac1,0x1f
0+009c <[^>]*> 7c01093c 	dextr_r\.w	at,\$ac1,0x0
0+00a0 <[^>]*> 7c21093c 	dextr_r\.w	at,\$ac1,0x1
0+00a4 <[^>]*> 7fe1093c 	dextr_r\.w	at,\$ac1,0x1f
0+00a8 <[^>]*> 7c0211bc 	dextr_rs\.w	v0,\$ac2,0x0
0+00ac <[^>]*> 7c2211bc 	dextr_rs\.w	v0,\$ac2,0x1
0+00b0 <[^>]*> 7fe211bc 	dextr_rs\.w	v0,\$ac2,0x1f
0+00b4 <[^>]*> 7c0213bc 	dextr_s\.h	v0,\$ac2,0x0
0+00b8 <[^>]*> 7c2213bc 	dextr_s\.h	v0,\$ac2,0x1
0+00bc <[^>]*> 7fe213bc 	dextr_s\.h	v0,\$ac2,0x1f
0+00c0 <[^>]*> 7c00003c 	dextr\.w	zero,\$ac0,0x0
0+00c4 <[^>]*> 7c20003c 	dextr\.w	zero,\$ac0,0x1
0+00c8 <[^>]*> 7fe0003c 	dextr\.w	zero,\$ac0,0x1f
0+00cc <[^>]*> 7d8b187c 	dextrv\.w	t3,\$ac3,t4
0+00d0 <[^>]*> 7dac017c 	dextrv_r\.w	t4,\$ac0,t5
0+00d4 <[^>]*> 7dcd09fc 	dextrv_rs\.w	t5,\$ac1,t6
0+00d8 <[^>]*> 7dee147c 	dextrv\.l	t6,\$ac2,t7
0+00dc <[^>]*> 7e0f1d7c 	dextrv_r\.l	t7,\$ac3,s0
0+00e0 <[^>]*> 7e3005fc 	dextrv_rs\.l	s0,\$ac0,s1
0+00e4 <[^>]*> 7f7a000d 	dinsv	k0,k1
0+00e8 <[^>]*> 7e950e74 	dmadd	\$ac1,s4,s5
0+00ec <[^>]*> 7eb61774 	dmaddu	\$ac2,s5,s6
0+00f0 <[^>]*> 7ed71ef4 	dmsub	\$ac3,s6,s7
0+00f4 <[^>]*> 7ef807f4 	dmsubu	\$ac0,s7,t8
0+00f8 <[^>]*> 7c8017fc 	dmthlip	a0,\$ac2
0+00fc <[^>]*> 7c010b34 	dpaq_sa\.l\.pw	\$ac1,zero,at
0+0100 <[^>]*> 7eb61134 	dpaq_s\.w\.qh	\$ac2,s5,s6
0+0104 <[^>]*> 7df000f4 	dpau\.h\.obl	\$ac0,t7,s0
0+0108 <[^>]*> 7e1109f4 	dpau\.h\.obr	\$ac1,s0,s1
0+010c <[^>]*> 7c640374 	dpsq_sa\.l\.pw	\$ac0,v1,a0
0+0110 <[^>]*> 7f190974 	dpsq_s\.w\.qh	\$ac1,t8,t9
0+0114 <[^>]*> 7e3212f4 	dpsu\.h\.obl	\$ac2,s1,s2
0+0118 <[^>]*> 7e531bf4 	dpsu\.h\.obr	\$ac3,s2,s3
0+011c <[^>]*> 7e001ebc 	dshilo	\$ac3,-64
0+0120 <[^>]*> 7df81ebc 	dshilo	\$ac3,63
0+0124 <[^>]*> 7c4006fc 	dshilov	\$ac0,v0
0+0128 <[^>]*> 7e51820a 	ldx	s0,s1\(s2\)
0+012c <[^>]*> 7d4b1c34 	maq_sa\.w\.qhll	\$ac3,t2,t3
0+0130 <[^>]*> 7d6c0474 	maq_sa\.w\.qhlr	\$ac0,t3,t4
0+0134 <[^>]*> 7d8d0cb4 	maq_sa\.w\.qhrl	\$ac1,t4,t5
0+0138 <[^>]*> 7dae14f4 	maq_sa\.w\.qhrr	\$ac2,t5,t6
0+013c <[^>]*> 7e110f34 	maq_s\.l\.pwl	\$ac1,s0,s1
0+0140 <[^>]*> 7e3217b4 	maq_s\.l\.pwr	\$ac2,s1,s2
0+0144 <[^>]*> 7d4b1d34 	maq_s\.w\.qhll	\$ac3,t2,t3
0+0148 <[^>]*> 7d6c0574 	maq_s\.w\.qhlr	\$ac0,t3,t4
0+014c <[^>]*> 7d8d0db4 	maq_s\.w\.qhrl	\$ac1,t4,t5
0+0150 <[^>]*> 7dae15f4 	maq_s\.w\.qhrr	\$ac2,t5,t6
0+0154 <[^>]*> 7d8d5f14 	muleq_s\.pw\.qhl	t3,t4,t5
0+0158 <[^>]*> 7dae6754 	muleq_s\.pw\.qhr	t4,t5,t6
0+015c <[^>]*> 7ca62194 	muleu_s\.qh\.obl	a0,a1,a2
0+0160 <[^>]*> 7cc729d4 	muleu_s\.qh\.obr	a1,a2,a3
0+0164 <[^>]*> 7ce837d0 	mulq_rs\.ph	a2,a3,t0
0+0168 <[^>]*> 7d2a47d4 	mulq_rs\.qh	t0,t1,t2
0+016c <[^>]*> 7f7c01b4 	mulsaq_s\.w\.qh	\$ac0,k1,gp
0+0170 <[^>]*> 7fbe13b4 	mulsaq_s\.l\.pw	\$ac2,sp,s8
0+0174 <[^>]*> 7fbee395 	packrl\.pw	gp,sp,s8
0+0178 <[^>]*> 7f5bc8d5 	pick\.ob	t9,k0,k1
0+017c <[^>]*> 7f7cd2d5 	pick\.qh	k0,k1,gp
0+0180 <[^>]*> 7f9ddcd5 	pick\.pw	k1,gp,sp
0+0184 <[^>]*> 7c0f7316 	preceq\.pw\.qhl	t6,t7
0+0188 <[^>]*> 7c107b56 	preceq\.pw\.qhr	t7,s0
0+018c <[^>]*> 7c118396 	preceq\.pw\.qhla	s0,s1
0+0190 <[^>]*> 7c128bd6 	preceq\.pw\.qhra	s1,s2
0+0194 <[^>]*> 7c139516 	preceq\.s\.l\.pwl	s2,s3
0+0198 <[^>]*> 7c149d56 	preceq\.s\.l\.pwr	s3,s4
0+019c <[^>]*> 7c19c116 	precequ\.pw\.qhl	t8,t9
0+01a0 <[^>]*> 7c1ac956 	precequ\.pw\.qhr	t9,k0
0+01a4 <[^>]*> 7c1bd196 	precequ\.pw\.qhla	k0,k1
0+01a8 <[^>]*> 7c1cd9d6 	precequ\.pw\.qhra	k1,gp
0+01ac <[^>]*> 7c1de716 	preceu\.qh\.obl	gp,sp
0+01b0 <[^>]*> 7c1eef56 	preceu\.qh\.obr	sp,s8
0+01b4 <[^>]*> 7c1ff796 	preceu\.qh\.obla	s8,ra
0+01b8 <[^>]*> 7c00ffd6 	preceu\.qh\.obra	ra,zero
0+01bc <[^>]*> 7ca62315 	precrq\.ob\.qh	a0,a1,a2
0+01c0 <[^>]*> 7d093f15 	precrq\.pw\.l	a3,t0,t1
0+01c4 <[^>]*> 7cc72d15 	precrq\.qh\.pw	a1,a2,a3
0+01c8 <[^>]*> 7ce83555 	precrq_rs\.qh\.pw	a2,a3,t0
0+01cc <[^>]*> 7d4b4bd5 	precrqu_s\.ob\.qh	t1,t2,t3
0+01d0 <[^>]*> 7f60d514 	raddu\.l\.ob	k0,k1
0+01d4 <[^>]*> 7c00e896 	repl\.ob	sp,0x0
0+01d8 <[^>]*> 7cffe896 	repl\.ob	sp,0xff
0+01dc <[^>]*> 7c1ff0d6 	replv\.ob	s8,ra
0+01e0 <[^>]*> 7e000a96 	repl\.qh	at,-512
0+01e4 <[^>]*> 7dff0a96 	repl\.qh	at,511
0+01e8 <[^>]*> 7c0312d6 	replv\.qh	v0,v1
0+01ec <[^>]*> 7e001c96 	repl\.pw	v1,-512
0+01f0 <[^>]*> 7dff1c96 	repl\.pw	v1,511
0+01f4 <[^>]*> 7c0524d6 	replv\.pw	a0,a1
0+01f8 <[^>]*> 7c031017 	shll\.ob	v0,v1,0x0
0+01fc <[^>]*> 7ce31017 	shll\.ob	v0,v1,0x7
0+0200 <[^>]*> 7ca41897 	shllv\.ob	v1,a0,a1
0+0204 <[^>]*> 7c094217 	shll\.qh	t0,t1,0x0
0+0208 <[^>]*> 7de94217 	shll\.qh	t0,t1,0xf
0+020c <[^>]*> 7d6a4a97 	shllv\.qh	t1,t2,t3
0+0210 <[^>]*> 7c0b5317 	shll_s\.qh	t2,t3,0x0
0+0214 <[^>]*> 7deb5317 	shll_s\.qh	t2,t3,0xf
0+0218 <[^>]*> 7dac5b97 	shllv_s\.qh	t3,t4,t5
0+021c <[^>]*> 7c0f7417 	shll\.pw	t6,t7,0x0
0+0220 <[^>]*> 7fef7417 	shll\.pw	t6,t7,0x1f
0+0224 <[^>]*> 7e307c97 	shllv\.pw	t7,s0,s1
0+0228 <[^>]*> 7c118517 	shll_s\.pw	s0,s1,0x0
0+022c <[^>]*> 7ff18517 	shll_s\.pw	s0,s1,0x1f
0+0230 <[^>]*> 7e728d97 	shllv_s\.pw	s1,s2,s3
0+0234 <[^>]*> 7c1de257 	shra\.qh	gp,sp,0x0
0+0238 <[^>]*> 7dfde257 	shra\.qh	gp,sp,0xf
0+023c <[^>]*> 7ffeead7 	shrav\.qh	sp,s8,ra
0+0240 <[^>]*> 7c1ff357 	shra_r\.qh	s8,ra,0x0
0+0244 <[^>]*> 7dfff357 	shra_r\.qh	s8,ra,0xf
0+0248 <[^>]*> 7c20fbd7 	shrav_r\.qh	ra,zero,at
0+024c <[^>]*> 7c010457 	shra\.pw	zero,at,0x0
0+0250 <[^>]*> 7fe10457 	shra\.pw	zero,at,0x1f
0+0254 <[^>]*> 7c620cd7 	shrav\.pw	at,v0,v1
0+0258 <[^>]*> 7c031557 	shra_r\.pw	v0,v1,0x0
0+025c <[^>]*> 7fe31557 	shra_r\.pw	v0,v1,0x1f
0+0260 <[^>]*> 7ca41dd7 	shrav_r\.pw	v1,a0,a1
0+0264 <[^>]*> 7c15a057 	shrl\.ob	s4,s5,0x0
0+0268 <[^>]*> 7cf5a057 	shrl\.ob	s4,s5,0x7
0+026c <[^>]*> 7ef6a8d7 	shrlv\.ob	s5,s6,s7
0+0270 <[^>]*> 7e3282d4 	subq\.qh	s0,s1,s2
0+0274 <[^>]*> 7e538bd4 	subq_s\.qh	s1,s2,s3
0+0278 <[^>]*> 7e7494d4 	subq\.pw	s2,s3,s4
0+027c <[^>]*> 7e959dd4 	subq_s\.pw	s3,s4,s5
0+0280 <[^>]*> 7eb6a054 	subu\.ob	s4,s5,s6
0+0284 <[^>]*> 7ed7a954 	subu_s\.ob	s5,s6,s7
	\.\.\.
