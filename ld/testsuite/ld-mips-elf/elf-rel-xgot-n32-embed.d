#name: MIPS ELF xgot reloc n32
#as: -EB -n32 -KPIC -xgot
#source: ../../../gas/testsuite/gas/mips/elf-rel-got-n32.s
#ld:
#objdump: -D --show-raw-insn

.*: +file format elf32-n.*mips.*

Disassembly of section \.reginfo:

10000078 <\.reginfo>:
10000078:	92020022 	.*
	\.\.\.
1000008c:	10018760 	.*

Disassembly of section \.text:

10000074 <fn>:
10000074:	3c050000 	lui	a1,0x0
10000078:	00bc2821 	addu	a1,a1,gp
1000007c:	8ca58018 	lw	a1,-32744\(a1\)
10000080:	3c050000 	lui	a1,0x0
10000084:	00bc2821 	addu	a1,a1,gp
10000088:	8ca58018 	lw	a1,-32744\(a1\)
1000008c:	24a5000c 	addiu	a1,a1,12
10000090:	3c050000 	lui	a1,0x0
10000094:	00bc2821 	addu	a1,a1,gp
10000098:	8ca58018 	lw	a1,-32744\(a1\)
1000009c:	3c010001 	lui	at,0x1
100000a0:	3421e240 	ori	at,at,0xe240
100000a4:	00a12821 	addu	a1,a1,at
100000a8:	3c050000 	lui	a1,0x0
100000ac:	00bc2821 	addu	a1,a1,gp
100000b0:	8ca58018 	lw	a1,-32744\(a1\)
100000b4:	00b12821 	addu	a1,a1,s1
100000b8:	3c050000 	lui	a1,0x0
100000bc:	00bc2821 	addu	a1,a1,gp
100000c0:	8ca58018 	lw	a1,-32744\(a1\)
100000c4:	24a5000c 	addiu	a1,a1,12
100000c8:	00b12821 	addu	a1,a1,s1
100000cc:	3c050000 	lui	a1,0x0
100000d0:	00bc2821 	addu	a1,a1,gp
100000d4:	8ca58018 	lw	a1,-32744\(a1\)
100000d8:	3c010001 	lui	at,0x1
100000dc:	3421e240 	ori	at,at,0xe240
100000e0:	00a12821 	addu	a1,a1,at
100000e4:	00b12821 	addu	a1,a1,s1
100000e8:	3c050000 	lui	a1,0x0
100000ec:	00bc2821 	addu	a1,a1,gp
100000f0:	8ca58018 	lw	a1,-32744\(a1\)
100000f4:	8ca50000 	lw	a1,0\(a1\)
100000f8:	3c050000 	lui	a1,0x0
100000fc:	00bc2821 	addu	a1,a1,gp
10000100:	8ca58018 	lw	a1,-32744\(a1\)
10000104:	8ca5000c 	lw	a1,12\(a1\)
10000108:	3c050000 	lui	a1,0x0
1000010c:	00bc2821 	addu	a1,a1,gp
10000110:	8ca58018 	lw	a1,-32744\(a1\)
10000114:	00b12821 	addu	a1,a1,s1
10000118:	8ca50000 	lw	a1,0\(a1\)
1000011c:	3c050000 	lui	a1,0x0
10000120:	00bc2821 	addu	a1,a1,gp
10000124:	8ca58018 	lw	a1,-32744\(a1\)
10000128:	00b12821 	addu	a1,a1,s1
1000012c:	8ca5000c 	lw	a1,12\(a1\)
10000130:	3c010000 	lui	at,0x0
10000134:	003c0821 	addu	at,at,gp
10000138:	8c218018 	lw	at,-32744\(at\)
1000013c:	00250821 	addu	at,at,a1
10000140:	8c250022 	lw	a1,34\(at\)
10000144:	3c010000 	lui	at,0x0
10000148:	003c0821 	addu	at,at,gp
1000014c:	8c218018 	lw	at,-32744\(at\)
10000150:	00250821 	addu	at,at,a1
10000154:	ac250038 	sw	a1,56\(at\)
10000158:	3c010000 	lui	at,0x0
1000015c:	003c0821 	addu	at,at,gp
10000160:	8c218018 	lw	at,-32744\(at\)
10000164:	88250000 	lwl	a1,0\(at\)
10000168:	98250003 	lwr	a1,3\(at\)
1000016c:	3c010000 	lui	at,0x0
10000170:	003c0821 	addu	at,at,gp
10000174:	8c218018 	lw	at,-32744\(at\)
10000178:	2421000c 	addiu	at,at,12
1000017c:	88250000 	lwl	a1,0\(at\)
10000180:	98250003 	lwr	a1,3\(at\)
10000184:	3c010000 	lui	at,0x0
10000188:	003c0821 	addu	at,at,gp
1000018c:	8c218018 	lw	at,-32744\(at\)
10000190:	00310821 	addu	at,at,s1
10000194:	88250000 	lwl	a1,0\(at\)
10000198:	98250003 	lwr	a1,3\(at\)
1000019c:	3c010000 	lui	at,0x0
100001a0:	003c0821 	addu	at,at,gp
100001a4:	8c218018 	lw	at,-32744\(at\)
100001a8:	2421000c 	addiu	at,at,12
100001ac:	00310821 	addu	at,at,s1
100001b0:	88250000 	lwl	a1,0\(at\)
100001b4:	98250003 	lwr	a1,3\(at\)
100001b8:	3c010000 	lui	at,0x0
100001bc:	003c0821 	addu	at,at,gp
100001c0:	8c218018 	lw	at,-32744\(at\)
100001c4:	24210022 	addiu	at,at,34
100001c8:	00250821 	addu	at,at,a1
100001cc:	88250000 	lwl	a1,0\(at\)
100001d0:	98250003 	lwr	a1,3\(at\)
100001d4:	3c010000 	lui	at,0x0
100001d8:	003c0821 	addu	at,at,gp
100001dc:	8c218018 	lw	at,-32744\(at\)
100001e0:	24210038 	addiu	at,at,56
100001e4:	00250821 	addu	at,at,a1
100001e8:	a8250000 	swl	a1,0\(at\)
100001ec:	b8250003 	swr	a1,3\(at\)
100001f0:	8f85801c 	lw	a1,-32740\(gp\)
100001f4:	24a506b8 	addiu	a1,a1,1720
100001f8:	8f85801c 	lw	a1,-32740\(gp\)
100001fc:	24a506c4 	addiu	a1,a1,1732
10000200:	8f858020 	lw	a1,-32736\(gp\)
10000204:	24a5e8f8 	addiu	a1,a1,-5896
10000208:	8f85801c 	lw	a1,-32740\(gp\)
1000020c:	24a506b8 	addiu	a1,a1,1720
10000210:	00b12821 	addu	a1,a1,s1
10000214:	8f85801c 	lw	a1,-32740\(gp\)
10000218:	24a506c4 	addiu	a1,a1,1732
1000021c:	00b12821 	addu	a1,a1,s1
10000220:	8f858020 	lw	a1,-32736\(gp\)
10000224:	24a5e8f8 	addiu	a1,a1,-5896
10000228:	00b12821 	addu	a1,a1,s1
1000022c:	8f85801c 	lw	a1,-32740\(gp\)
10000230:	8ca506b8 	lw	a1,1720\(a1\)
10000234:	8f85801c 	lw	a1,-32740\(gp\)
10000238:	8ca506c4 	lw	a1,1732\(a1\)
1000023c:	8f85801c 	lw	a1,-32740\(gp\)
10000240:	00b12821 	addu	a1,a1,s1
10000244:	8ca506b8 	lw	a1,1720\(a1\)
10000248:	8f85801c 	lw	a1,-32740\(gp\)
1000024c:	00b12821 	addu	a1,a1,s1
10000250:	8ca506c4 	lw	a1,1732\(a1\)
10000254:	8f81801c 	lw	at,-32740\(gp\)
10000258:	00250821 	addu	at,at,a1
1000025c:	8c2506da 	lw	a1,1754\(at\)
10000260:	8f81801c 	lw	at,-32740\(gp\)
10000264:	00250821 	addu	at,at,a1
10000268:	ac2506f0 	sw	a1,1776\(at\)
1000026c:	8f81801c 	lw	at,-32740\(gp\)
10000270:	242106b8 	addiu	at,at,1720
10000274:	88250000 	lwl	a1,0\(at\)
10000278:	98250003 	lwr	a1,3\(at\)
1000027c:	8f81801c 	lw	at,-32740\(gp\)
10000280:	242106c4 	addiu	at,at,1732
10000284:	88250000 	lwl	a1,0\(at\)
10000288:	98250003 	lwr	a1,3\(at\)
1000028c:	8f81801c 	lw	at,-32740\(gp\)
10000290:	242106b8 	addiu	at,at,1720
10000294:	00310821 	addu	at,at,s1
10000298:	88250000 	lwl	a1,0\(at\)
1000029c:	98250003 	lwr	a1,3\(at\)
100002a0:	8f81801c 	lw	at,-32740\(gp\)
100002a4:	242106c4 	addiu	at,at,1732
100002a8:	00310821 	addu	at,at,s1
100002ac:	88250000 	lwl	a1,0\(at\)
100002b0:	98250003 	lwr	a1,3\(at\)
100002b4:	8f81801c 	lw	at,-32740\(gp\)
100002b8:	242106da 	addiu	at,at,1754
100002bc:	00250821 	addu	at,at,a1
100002c0:	88250000 	lwl	a1,0\(at\)
100002c4:	98250003 	lwr	a1,3\(at\)
100002c8:	8f81801c 	lw	at,-32740\(gp\)
100002cc:	242106f0 	addiu	at,at,1776
100002d0:	00250821 	addu	at,at,a1
100002d4:	a8250000 	swl	a1,0\(at\)
100002d8:	b8250003 	swr	a1,3\(at\)
100002dc:	3c050000 	lui	a1,0x0
100002e0:	00bc2821 	addu	a1,a1,gp
100002e4:	8ca58024 	lw	a1,-32732\(a1\)
100002e8:	8f858028 	lw	a1,-32728\(gp\)
100002ec:	24a50074 	addiu	a1,a1,116
100002f0:	3c190000 	lui	t9,0x0
100002f4:	033cc821 	addu	t9,t9,gp
100002f8:	8f398024 	lw	t9,-32732\(t9\)
100002fc:	8f998028 	lw	t9,-32728\(gp\)
10000300:	27390074 	addiu	t9,t9,116
10000304:	3c190000 	lui	t9,0x0
10000308:	033cc821 	addu	t9,t9,gp
1000030c:	8f398024 	lw	t9,-32732\(t9\)
10000310:	0411ff58 	bal	10000074 <fn>
10000314:	00000000 	nop
10000318:	8f998028 	lw	t9,-32728\(gp\)
1000031c:	27390074 	addiu	t9,t9,116
10000320:	0411ff54 	bal	10000074 <fn>
10000324:	00000000 	nop
10000328:	3c050000 	lui	a1,0x0
1000032c:	00bc2821 	addu	a1,a1,gp
10000330:	8ca5802c 	lw	a1,-32724\(a1\)
10000334:	3c050000 	lui	a1,0x0
10000338:	00bc2821 	addu	a1,a1,gp
1000033c:	8ca5802c 	lw	a1,-32724\(a1\)
10000340:	24a5000c 	addiu	a1,a1,12
10000344:	3c050000 	lui	a1,0x0
10000348:	00bc2821 	addu	a1,a1,gp
1000034c:	8ca5802c 	lw	a1,-32724\(a1\)
10000350:	3c010001 	lui	at,0x1
10000354:	3421e240 	ori	at,at,0xe240
10000358:	00a12821 	addu	a1,a1,at
1000035c:	3c050000 	lui	a1,0x0
10000360:	00bc2821 	addu	a1,a1,gp
10000364:	8ca5802c 	lw	a1,-32724\(a1\)
10000368:	00b12821 	addu	a1,a1,s1
1000036c:	3c050000 	lui	a1,0x0
10000370:	00bc2821 	addu	a1,a1,gp
10000374:	8ca5802c 	lw	a1,-32724\(a1\)
10000378:	24a5000c 	addiu	a1,a1,12
1000037c:	00b12821 	addu	a1,a1,s1
10000380:	3c050000 	lui	a1,0x0
10000384:	00bc2821 	addu	a1,a1,gp
10000388:	8ca5802c 	lw	a1,-32724\(a1\)
1000038c:	3c010001 	lui	at,0x1
10000390:	3421e240 	ori	at,at,0xe240
10000394:	00a12821 	addu	a1,a1,at
10000398:	00b12821 	addu	a1,a1,s1
1000039c:	3c050000 	lui	a1,0x0
100003a0:	00bc2821 	addu	a1,a1,gp
100003a4:	8ca5802c 	lw	a1,-32724\(a1\)
100003a8:	8ca50000 	lw	a1,0\(a1\)
100003ac:	3c050000 	lui	a1,0x0
100003b0:	00bc2821 	addu	a1,a1,gp
100003b4:	8ca5802c 	lw	a1,-32724\(a1\)
100003b8:	8ca5000c 	lw	a1,12\(a1\)
100003bc:	3c050000 	lui	a1,0x0
100003c0:	00bc2821 	addu	a1,a1,gp
100003c4:	8ca5802c 	lw	a1,-32724\(a1\)
100003c8:	00b12821 	addu	a1,a1,s1
100003cc:	8ca50000 	lw	a1,0\(a1\)
100003d0:	3c050000 	lui	a1,0x0
100003d4:	00bc2821 	addu	a1,a1,gp
100003d8:	8ca5802c 	lw	a1,-32724\(a1\)
100003dc:	00b12821 	addu	a1,a1,s1
100003e0:	8ca5000c 	lw	a1,12\(a1\)
100003e4:	3c010000 	lui	at,0x0
100003e8:	003c0821 	addu	at,at,gp
100003ec:	8c21802c 	lw	at,-32724\(at\)
100003f0:	00250821 	addu	at,at,a1
100003f4:	8c250022 	lw	a1,34\(at\)
100003f8:	3c010000 	lui	at,0x0
100003fc:	003c0821 	addu	at,at,gp
10000400:	8c21802c 	lw	at,-32724\(at\)
10000404:	00250821 	addu	at,at,a1
10000408:	ac250038 	sw	a1,56\(at\)
1000040c:	3c010000 	lui	at,0x0
10000410:	003c0821 	addu	at,at,gp
10000414:	8c21802c 	lw	at,-32724\(at\)
10000418:	88250000 	lwl	a1,0\(at\)
1000041c:	98250003 	lwr	a1,3\(at\)
10000420:	3c010000 	lui	at,0x0
10000424:	003c0821 	addu	at,at,gp
10000428:	8c21802c 	lw	at,-32724\(at\)
1000042c:	2421000c 	addiu	at,at,12
10000430:	88250000 	lwl	a1,0\(at\)
10000434:	98250003 	lwr	a1,3\(at\)
10000438:	3c010000 	lui	at,0x0
1000043c:	003c0821 	addu	at,at,gp
10000440:	8c21802c 	lw	at,-32724\(at\)
10000444:	00310821 	addu	at,at,s1
10000448:	88250000 	lwl	a1,0\(at\)
1000044c:	98250003 	lwr	a1,3\(at\)
10000450:	3c010000 	lui	at,0x0
10000454:	003c0821 	addu	at,at,gp
10000458:	8c21802c 	lw	at,-32724\(at\)
1000045c:	2421000c 	addiu	at,at,12
10000460:	00310821 	addu	at,at,s1
10000464:	88250000 	lwl	a1,0\(at\)
10000468:	98250003 	lwr	a1,3\(at\)
1000046c:	3c010000 	lui	at,0x0
10000470:	003c0821 	addu	at,at,gp
10000474:	8c21802c 	lw	at,-32724\(at\)
10000478:	24210022 	addiu	at,at,34
1000047c:	00250821 	addu	at,at,a1
10000480:	88250000 	lwl	a1,0\(at\)
10000484:	98250003 	lwr	a1,3\(at\)
10000488:	3c010000 	lui	at,0x0
1000048c:	003c0821 	addu	at,at,gp
10000490:	8c21802c 	lw	at,-32724\(at\)
10000494:	24210038 	addiu	at,at,56
10000498:	00250821 	addu	at,at,a1
1000049c:	a8250000 	swl	a1,0\(at\)
100004a0:	b8250003 	swr	a1,3\(at\)
100004a4:	8f85801c 	lw	a1,-32740\(gp\)
100004a8:	24a50730 	addiu	a1,a1,1840
100004ac:	8f85801c 	lw	a1,-32740\(gp\)
100004b0:	24a5073c 	addiu	a1,a1,1852
100004b4:	8f858020 	lw	a1,-32736\(gp\)
100004b8:	24a5e970 	addiu	a1,a1,-5776
100004bc:	8f85801c 	lw	a1,-32740\(gp\)
100004c0:	24a50730 	addiu	a1,a1,1840
100004c4:	00b12821 	addu	a1,a1,s1
100004c8:	8f85801c 	lw	a1,-32740\(gp\)
100004cc:	24a5073c 	addiu	a1,a1,1852
100004d0:	00b12821 	addu	a1,a1,s1
100004d4:	8f858020 	lw	a1,-32736\(gp\)
100004d8:	24a5e970 	addiu	a1,a1,-5776
100004dc:	00b12821 	addu	a1,a1,s1
100004e0:	8f85801c 	lw	a1,-32740\(gp\)
100004e4:	8ca50730 	lw	a1,1840\(a1\)
100004e8:	8f85801c 	lw	a1,-32740\(gp\)
100004ec:	8ca5073c 	lw	a1,1852\(a1\)
100004f0:	8f85801c 	lw	a1,-32740\(gp\)
100004f4:	00b12821 	addu	a1,a1,s1
100004f8:	8ca50730 	lw	a1,1840\(a1\)
100004fc:	8f85801c 	lw	a1,-32740\(gp\)
10000500:	00b12821 	addu	a1,a1,s1
10000504:	8ca5073c 	lw	a1,1852\(a1\)
10000508:	8f81801c 	lw	at,-32740\(gp\)
1000050c:	00250821 	addu	at,at,a1
10000510:	8c250752 	lw	a1,1874\(at\)
10000514:	8f81801c 	lw	at,-32740\(gp\)
10000518:	00250821 	addu	at,at,a1
1000051c:	ac250768 	sw	a1,1896\(at\)
10000520:	8f81801c 	lw	at,-32740\(gp\)
10000524:	24210730 	addiu	at,at,1840
10000528:	88250000 	lwl	a1,0\(at\)
1000052c:	98250003 	lwr	a1,3\(at\)
10000530:	8f81801c 	lw	at,-32740\(gp\)
10000534:	2421073c 	addiu	at,at,1852
10000538:	88250000 	lwl	a1,0\(at\)
1000053c:	98250003 	lwr	a1,3\(at\)
10000540:	8f81801c 	lw	at,-32740\(gp\)
10000544:	24210730 	addiu	at,at,1840
10000548:	00310821 	addu	at,at,s1
1000054c:	88250000 	lwl	a1,0\(at\)
10000550:	98250003 	lwr	a1,3\(at\)
10000554:	8f81801c 	lw	at,-32740\(gp\)
10000558:	2421073c 	addiu	at,at,1852
1000055c:	00310821 	addu	at,at,s1
10000560:	88250000 	lwl	a1,0\(at\)
10000564:	98250003 	lwr	a1,3\(at\)
10000568:	8f81801c 	lw	at,-32740\(gp\)
1000056c:	24210752 	addiu	at,at,1874
10000570:	00250821 	addu	at,at,a1
10000574:	88250000 	lwl	a1,0\(at\)
10000578:	98250003 	lwr	a1,3\(at\)
1000057c:	8f81801c 	lw	at,-32740\(gp\)
10000580:	24210768 	addiu	at,at,1896
10000584:	00250821 	addu	at,at,a1
10000588:	a8250000 	swl	a1,0\(at\)
1000058c:	b8250003 	swr	a1,3\(at\)
10000590:	3c050000 	lui	a1,0x0
10000594:	00bc2821 	addu	a1,a1,gp
10000598:	8ca58030 	lw	a1,-32720\(a1\)
1000059c:	8f858028 	lw	a1,-32728\(gp\)
100005a0:	24a50674 	addiu	a1,a1,1652
100005a4:	3c190000 	lui	t9,0x0
100005a8:	033cc821 	addu	t9,t9,gp
100005ac:	8f398030 	lw	t9,-32720\(t9\)
100005b0:	8f998028 	lw	t9,-32728\(gp\)
100005b4:	27390674 	addiu	t9,t9,1652
100005b8:	3c190000 	lui	t9,0x0
100005bc:	033cc821 	addu	t9,t9,gp
100005c0:	8f398030 	lw	t9,-32720\(t9\)
100005c4:	0411002b 	bal	10000674 <fn2>
100005c8:	00000000 	nop
100005cc:	8f998028 	lw	t9,-32728\(gp\)
100005d0:	27390674 	addiu	t9,t9,1652
100005d4:	04110027 	bal	10000674 <fn2>
100005d8:	00000000 	nop
100005dc:	3c050000 	lui	a1,0x0
100005e0:	00bc2821 	addu	a1,a1,gp
100005e4:	8ca58018 	lw	a1,-32744\(a1\)
100005e8:	1000fea2 	b	10000074 <fn>
100005ec:	00000000 	nop
100005f0:	3c050000 	lui	a1,0x0
100005f4:	00bc2821 	addu	a1,a1,gp
100005f8:	8ca5802c 	lw	a1,-32724\(a1\)
100005fc:	8ca50000 	lw	a1,0\(a1\)
10000600:	1000001c 	b	10000674 <fn2>
10000604:	00000000 	nop
10000608:	8f85801c 	lw	a1,-32740\(gp\)
1000060c:	24a506b8 	addiu	a1,a1,1720
10000610:	1000fe98 	b	10000074 <fn>
10000614:	00000000 	nop
10000618:	8f85801c 	lw	a1,-32740\(gp\)
1000061c:	24a5073c 	addiu	a1,a1,1852
10000620:	10000014 	b	10000674 <fn2>
10000624:	00000000 	nop
10000628:	8f858020 	lw	a1,-32736\(gp\)
1000062c:	24a5e8f8 	addiu	a1,a1,-5896
10000630:	1000fe90 	b	10000074 <fn>
10000634:	00000000 	nop
10000638:	8f85801c 	lw	a1,-32740\(gp\)
1000063c:	8ca50730 	lw	a1,1840\(a1\)
10000640:	1000000c 	b	10000674 <fn2>
10000644:	00000000 	nop
10000648:	8f85801c 	lw	a1,-32740\(gp\)
1000064c:	8ca506c4 	lw	a1,1732\(a1\)
10000650:	1000fe88 	b	10000074 <fn>
10000654:	00000000 	nop
10000658:	8f81801c 	lw	at,-32740\(gp\)
1000065c:	00250821 	addu	at,at,a1
10000660:	8c250752 	lw	a1,1874\(at\)
10000664:	10000003 	b	10000674 <fn2>
10000668:	00000000 	nop
	\.\.\.

10000674 <fn2>:
	\.\.\.

Disassembly of section \.data:

1001067c <_fdata>:
	\.\.\.

100106b8 <dg1>:
	\.\.\.

100106f4 <sp2>:
	\.\.\.

10010730 <dg2>:
	\.\.\.

Disassembly of section \.got:

10010770 <_GLOBAL_OFFSET_TABLE_>:
10010770:	00000000 	.*
10010774:	80000000 	.*
10010778:	100106b8 	.*
1001077c:	10010000 	.*
10010780:	10030000 	.*
10010784:	10000074 	.*
10010788:	10000000 	.*
1001078c:	10010730 	.*
10010790:	10000674 	.*
10010794:	00000000 	.*
10010798:	00000000 	.*
#pass
