#name: MIPS ELF xgot reloc n64
#as: -EB -64 -KPIC -xgot
#source: ../../../gas/testsuite/gas/mips/elf-rel-got-n64.s
#ld:
#objdump: -D --show-raw-insn

.*: +file format elf64-.*mips.*

Disassembly of section \.MIPS\.options:

00000001200000b0 <\.MIPS\.options>:
   1200000b0:	01280000 	.*
   1200000b4:	00000000 	.*
   1200000b8:	92020022 	.*
	\.\.\.
   1200000d0:	00000001 	.*
   1200000d4:	200187a0 	.*

Disassembly of section \.text:

00000001200000b0 <fn>:
   1200000b0:	3c050000 	lui	a1,0x0
   1200000b4:	00bc282d 	daddu	a1,a1,gp
   1200000b8:	dca58020 	ld	a1,-32736\(a1\)
   1200000bc:	3c050000 	lui	a1,0x0
   1200000c0:	00bc282d 	daddu	a1,a1,gp
   1200000c4:	dca58020 	ld	a1,-32736\(a1\)
   1200000c8:	64a5000c 	daddiu	a1,a1,12
   1200000cc:	3c050000 	lui	a1,0x0
   1200000d0:	00bc282d 	daddu	a1,a1,gp
   1200000d4:	dca58020 	ld	a1,-32736\(a1\)
   1200000d8:	3c010001 	lui	at,0x1
   1200000dc:	3421e240 	ori	at,at,0xe240
   1200000e0:	00a1282d 	daddu	a1,a1,at
   1200000e4:	3c050000 	lui	a1,0x0
   1200000e8:	00bc282d 	daddu	a1,a1,gp
   1200000ec:	dca58020 	ld	a1,-32736\(a1\)
   1200000f0:	00b1282d 	daddu	a1,a1,s1
   1200000f4:	3c050000 	lui	a1,0x0
   1200000f8:	00bc282d 	daddu	a1,a1,gp
   1200000fc:	dca58020 	ld	a1,-32736\(a1\)
   120000100:	64a5000c 	daddiu	a1,a1,12
   120000104:	00b1282d 	daddu	a1,a1,s1
   120000108:	3c050000 	lui	a1,0x0
   12000010c:	00bc282d 	daddu	a1,a1,gp
   120000110:	dca58020 	ld	a1,-32736\(a1\)
   120000114:	3c010001 	lui	at,0x1
   120000118:	3421e240 	ori	at,at,0xe240
   12000011c:	00a1282d 	daddu	a1,a1,at
   120000120:	00b1282d 	daddu	a1,a1,s1
   120000124:	3c050000 	lui	a1,0x0
   120000128:	00bc282d 	daddu	a1,a1,gp
   12000012c:	dca58020 	ld	a1,-32736\(a1\)
   120000130:	dca50000 	ld	a1,0\(a1\)
   120000134:	3c050000 	lui	a1,0x0
   120000138:	00bc282d 	daddu	a1,a1,gp
   12000013c:	dca58020 	ld	a1,-32736\(a1\)
   120000140:	dca5000c 	ld	a1,12\(a1\)
   120000144:	3c050000 	lui	a1,0x0
   120000148:	00bc282d 	daddu	a1,a1,gp
   12000014c:	dca58020 	ld	a1,-32736\(a1\)
   120000150:	00b1282d 	daddu	a1,a1,s1
   120000154:	dca50000 	ld	a1,0\(a1\)
   120000158:	3c050000 	lui	a1,0x0
   12000015c:	00bc282d 	daddu	a1,a1,gp
   120000160:	dca58020 	ld	a1,-32736\(a1\)
   120000164:	00b1282d 	daddu	a1,a1,s1
   120000168:	dca5000c 	ld	a1,12\(a1\)
   12000016c:	3c010000 	lui	at,0x0
   120000170:	003c082d 	daddu	at,at,gp
   120000174:	dc218020 	ld	at,-32736\(at\)
   120000178:	0025082d 	daddu	at,at,a1
   12000017c:	dc250022 	ld	a1,34\(at\)
   120000180:	3c010000 	lui	at,0x0
   120000184:	003c082d 	daddu	at,at,gp
   120000188:	dc218020 	ld	at,-32736\(at\)
   12000018c:	0025082d 	daddu	at,at,a1
   120000190:	fc250038 	sd	a1,56\(at\)
   120000194:	3c010000 	lui	at,0x0
   120000198:	003c082d 	daddu	at,at,gp
   12000019c:	dc218020 	ld	at,-32736\(at\)
   1200001a0:	88250000 	lwl	a1,0\(at\)
   1200001a4:	98250003 	lwr	a1,3\(at\)
   1200001a8:	3c010000 	lui	at,0x0
   1200001ac:	003c082d 	daddu	at,at,gp
   1200001b0:	dc218020 	ld	at,-32736\(at\)
   1200001b4:	6421000c 	daddiu	at,at,12
   1200001b8:	88250000 	lwl	a1,0\(at\)
   1200001bc:	98250003 	lwr	a1,3\(at\)
   1200001c0:	3c010000 	lui	at,0x0
   1200001c4:	003c082d 	daddu	at,at,gp
   1200001c8:	dc218020 	ld	at,-32736\(at\)
   1200001cc:	0031082d 	daddu	at,at,s1
   1200001d0:	88250000 	lwl	a1,0\(at\)
   1200001d4:	98250003 	lwr	a1,3\(at\)
   1200001d8:	3c010000 	lui	at,0x0
   1200001dc:	003c082d 	daddu	at,at,gp
   1200001e0:	dc218020 	ld	at,-32736\(at\)
   1200001e4:	6421000c 	daddiu	at,at,12
   1200001e8:	0031082d 	daddu	at,at,s1
   1200001ec:	88250000 	lwl	a1,0\(at\)
   1200001f0:	98250003 	lwr	a1,3\(at\)
   1200001f4:	3c010000 	lui	at,0x0
   1200001f8:	003c082d 	daddu	at,at,gp
   1200001fc:	dc218020 	ld	at,-32736\(at\)
   120000200:	64210022 	daddiu	at,at,34
   120000204:	0025082d 	daddu	at,at,a1
   120000208:	88250000 	lwl	a1,0\(at\)
   12000020c:	98250003 	lwr	a1,3\(at\)
   120000210:	3c010000 	lui	at,0x0
   120000214:	003c082d 	daddu	at,at,gp
   120000218:	dc218020 	ld	at,-32736\(at\)
   12000021c:	64210038 	daddiu	at,at,56
   120000220:	0025082d 	daddu	at,at,a1
   120000224:	a8250000 	swl	a1,0\(at\)
   120000228:	b8250003 	swr	a1,3\(at\)
   12000022c:	df858028 	ld	a1,-32728\(gp\)
   120000230:	64a506f4 	daddiu	a1,a1,1780
   120000234:	df858028 	ld	a1,-32728\(gp\)
   120000238:	64a50700 	daddiu	a1,a1,1792
   12000023c:	df858030 	ld	a1,-32720\(gp\)
   120000240:	64a5e934 	daddiu	a1,a1,-5836
   120000244:	df858028 	ld	a1,-32728\(gp\)
   120000248:	64a506f4 	daddiu	a1,a1,1780
   12000024c:	00b1282d 	daddu	a1,a1,s1
   120000250:	df858028 	ld	a1,-32728\(gp\)
   120000254:	64a50700 	daddiu	a1,a1,1792
   120000258:	00b1282d 	daddu	a1,a1,s1
   12000025c:	df858030 	ld	a1,-32720\(gp\)
   120000260:	64a5e934 	daddiu	a1,a1,-5836
   120000264:	00b1282d 	daddu	a1,a1,s1
   120000268:	df858028 	ld	a1,-32728\(gp\)
   12000026c:	dca506f4 	ld	a1,1780\(a1\)
   120000270:	df858028 	ld	a1,-32728\(gp\)
   120000274:	dca50700 	ld	a1,1792\(a1\)
   120000278:	df858028 	ld	a1,-32728\(gp\)
   12000027c:	00b1282d 	daddu	a1,a1,s1
   120000280:	dca506f4 	ld	a1,1780\(a1\)
   120000284:	df858028 	ld	a1,-32728\(gp\)
   120000288:	00b1282d 	daddu	a1,a1,s1
   12000028c:	dca50700 	ld	a1,1792\(a1\)
   120000290:	df818028 	ld	at,-32728\(gp\)
   120000294:	0025082d 	daddu	at,at,a1
   120000298:	dc250716 	ld	a1,1814\(at\)
   12000029c:	df818028 	ld	at,-32728\(gp\)
   1200002a0:	0025082d 	daddu	at,at,a1
   1200002a4:	fc25072c 	sd	a1,1836\(at\)
   1200002a8:	df818028 	ld	at,-32728\(gp\)
   1200002ac:	642106f4 	daddiu	at,at,1780
   1200002b0:	88250000 	lwl	a1,0\(at\)
   1200002b4:	98250003 	lwr	a1,3\(at\)
   1200002b8:	df818028 	ld	at,-32728\(gp\)
   1200002bc:	64210700 	daddiu	at,at,1792
   1200002c0:	88250000 	lwl	a1,0\(at\)
   1200002c4:	98250003 	lwr	a1,3\(at\)
   1200002c8:	df818028 	ld	at,-32728\(gp\)
   1200002cc:	642106f4 	daddiu	at,at,1780
   1200002d0:	0031082d 	daddu	at,at,s1
   1200002d4:	88250000 	lwl	a1,0\(at\)
   1200002d8:	98250003 	lwr	a1,3\(at\)
   1200002dc:	df818028 	ld	at,-32728\(gp\)
   1200002e0:	64210700 	daddiu	at,at,1792
   1200002e4:	0031082d 	daddu	at,at,s1
   1200002e8:	88250000 	lwl	a1,0\(at\)
   1200002ec:	98250003 	lwr	a1,3\(at\)
   1200002f0:	df818028 	ld	at,-32728\(gp\)
   1200002f4:	64210716 	daddiu	at,at,1814
   1200002f8:	0025082d 	daddu	at,at,a1
   1200002fc:	88250000 	lwl	a1,0\(at\)
   120000300:	98250003 	lwr	a1,3\(at\)
   120000304:	df818028 	ld	at,-32728\(gp\)
   120000308:	6421072c 	daddiu	at,at,1836
   12000030c:	0025082d 	daddu	at,at,a1
   120000310:	a8250000 	swl	a1,0\(at\)
   120000314:	b8250003 	swr	a1,3\(at\)
   120000318:	3c050000 	lui	a1,0x0
   12000031c:	00bc282d 	daddu	a1,a1,gp
   120000320:	dca58038 	ld	a1,-32712\(a1\)
   120000324:	df858040 	ld	a1,-32704\(gp\)
   120000328:	64a500b0 	daddiu	a1,a1,176
   12000032c:	3c190000 	lui	t9,0x0
   120000330:	033cc82d 	daddu	t9,t9,gp
   120000334:	df398038 	ld	t9,-32712\(t9\)
   120000338:	df998040 	ld	t9,-32704\(gp\)
   12000033c:	673900b0 	daddiu	t9,t9,176
   120000340:	3c190000 	lui	t9,0x0
   120000344:	033cc82d 	daddu	t9,t9,gp
   120000348:	df398038 	ld	t9,-32712\(t9\)
   12000034c:	0411ff58 	bal	1200000b0 <fn>
   120000350:	00000000 	nop
   120000354:	df998040 	ld	t9,-32704\(gp\)
   120000358:	673900b0 	daddiu	t9,t9,176
   12000035c:	0411ff54 	bal	1200000b0 <fn>
   120000360:	00000000 	nop
   120000364:	3c050000 	lui	a1,0x0
   120000368:	00bc282d 	daddu	a1,a1,gp
   12000036c:	dca58048 	ld	a1,-32696\(a1\)
   120000370:	3c050000 	lui	a1,0x0
   120000374:	00bc282d 	daddu	a1,a1,gp
   120000378:	dca58048 	ld	a1,-32696\(a1\)
   12000037c:	64a5000c 	daddiu	a1,a1,12
   120000380:	3c050000 	lui	a1,0x0
   120000384:	00bc282d 	daddu	a1,a1,gp
   120000388:	dca58048 	ld	a1,-32696\(a1\)
   12000038c:	3c010001 	lui	at,0x1
   120000390:	3421e240 	ori	at,at,0xe240
   120000394:	00a1282d 	daddu	a1,a1,at
   120000398:	3c050000 	lui	a1,0x0
   12000039c:	00bc282d 	daddu	a1,a1,gp
   1200003a0:	dca58048 	ld	a1,-32696\(a1\)
   1200003a4:	00b1282d 	daddu	a1,a1,s1
   1200003a8:	3c050000 	lui	a1,0x0
   1200003ac:	00bc282d 	daddu	a1,a1,gp
   1200003b0:	dca58048 	ld	a1,-32696\(a1\)
   1200003b4:	64a5000c 	daddiu	a1,a1,12
   1200003b8:	00b1282d 	daddu	a1,a1,s1
   1200003bc:	3c050000 	lui	a1,0x0
   1200003c0:	00bc282d 	daddu	a1,a1,gp
   1200003c4:	dca58048 	ld	a1,-32696\(a1\)
   1200003c8:	3c010001 	lui	at,0x1
   1200003cc:	3421e240 	ori	at,at,0xe240
   1200003d0:	00a1282d 	daddu	a1,a1,at
   1200003d4:	00b1282d 	daddu	a1,a1,s1
   1200003d8:	3c050000 	lui	a1,0x0
   1200003dc:	00bc282d 	daddu	a1,a1,gp
   1200003e0:	dca58048 	ld	a1,-32696\(a1\)
   1200003e4:	dca50000 	ld	a1,0\(a1\)
   1200003e8:	3c050000 	lui	a1,0x0
   1200003ec:	00bc282d 	daddu	a1,a1,gp
   1200003f0:	dca58048 	ld	a1,-32696\(a1\)
   1200003f4:	dca5000c 	ld	a1,12\(a1\)
   1200003f8:	3c050000 	lui	a1,0x0
   1200003fc:	00bc282d 	daddu	a1,a1,gp
   120000400:	dca58048 	ld	a1,-32696\(a1\)
   120000404:	00b1282d 	daddu	a1,a1,s1
   120000408:	dca50000 	ld	a1,0\(a1\)
   12000040c:	3c050000 	lui	a1,0x0
   120000410:	00bc282d 	daddu	a1,a1,gp
   120000414:	dca58048 	ld	a1,-32696\(a1\)
   120000418:	00b1282d 	daddu	a1,a1,s1
   12000041c:	dca5000c 	ld	a1,12\(a1\)
   120000420:	3c010000 	lui	at,0x0
   120000424:	003c082d 	daddu	at,at,gp
   120000428:	dc218048 	ld	at,-32696\(at\)
   12000042c:	0025082d 	daddu	at,at,a1
   120000430:	dc250022 	ld	a1,34\(at\)
   120000434:	3c010000 	lui	at,0x0
   120000438:	003c082d 	daddu	at,at,gp
   12000043c:	dc218048 	ld	at,-32696\(at\)
   120000440:	0025082d 	daddu	at,at,a1
   120000444:	fc250038 	sd	a1,56\(at\)
   120000448:	3c010000 	lui	at,0x0
   12000044c:	003c082d 	daddu	at,at,gp
   120000450:	dc218048 	ld	at,-32696\(at\)
   120000454:	88250000 	lwl	a1,0\(at\)
   120000458:	98250003 	lwr	a1,3\(at\)
   12000045c:	3c010000 	lui	at,0x0
   120000460:	003c082d 	daddu	at,at,gp
   120000464:	dc218048 	ld	at,-32696\(at\)
   120000468:	6421000c 	daddiu	at,at,12
   12000046c:	88250000 	lwl	a1,0\(at\)
   120000470:	98250003 	lwr	a1,3\(at\)
   120000474:	3c010000 	lui	at,0x0
   120000478:	003c082d 	daddu	at,at,gp
   12000047c:	dc218048 	ld	at,-32696\(at\)
   120000480:	0031082d 	daddu	at,at,s1
   120000484:	88250000 	lwl	a1,0\(at\)
   120000488:	98250003 	lwr	a1,3\(at\)
   12000048c:	3c010000 	lui	at,0x0
   120000490:	003c082d 	daddu	at,at,gp
   120000494:	dc218048 	ld	at,-32696\(at\)
   120000498:	6421000c 	daddiu	at,at,12
   12000049c:	0031082d 	daddu	at,at,s1
   1200004a0:	88250000 	lwl	a1,0\(at\)
   1200004a4:	98250003 	lwr	a1,3\(at\)
   1200004a8:	3c010000 	lui	at,0x0
   1200004ac:	003c082d 	daddu	at,at,gp
   1200004b0:	dc218048 	ld	at,-32696\(at\)
   1200004b4:	64210022 	daddiu	at,at,34
   1200004b8:	0025082d 	daddu	at,at,a1
   1200004bc:	88250000 	lwl	a1,0\(at\)
   1200004c0:	98250003 	lwr	a1,3\(at\)
   1200004c4:	3c010000 	lui	at,0x0
   1200004c8:	003c082d 	daddu	at,at,gp
   1200004cc:	dc218048 	ld	at,-32696\(at\)
   1200004d0:	64210038 	daddiu	at,at,56
   1200004d4:	0025082d 	daddu	at,at,a1
   1200004d8:	a8250000 	swl	a1,0\(at\)
   1200004dc:	b8250003 	swr	a1,3\(at\)
   1200004e0:	df858028 	ld	a1,-32728\(gp\)
   1200004e4:	64a5076c 	daddiu	a1,a1,1900
   1200004e8:	df858028 	ld	a1,-32728\(gp\)
   1200004ec:	64a50778 	daddiu	a1,a1,1912
   1200004f0:	df858030 	ld	a1,-32720\(gp\)
   1200004f4:	64a5e9ac 	daddiu	a1,a1,-5716
   1200004f8:	df858028 	ld	a1,-32728\(gp\)
   1200004fc:	64a5076c 	daddiu	a1,a1,1900
   120000500:	00b1282d 	daddu	a1,a1,s1
   120000504:	df858028 	ld	a1,-32728\(gp\)
   120000508:	64a50778 	daddiu	a1,a1,1912
   12000050c:	00b1282d 	daddu	a1,a1,s1
   120000510:	df858030 	ld	a1,-32720\(gp\)
   120000514:	64a5e9ac 	daddiu	a1,a1,-5716
   120000518:	00b1282d 	daddu	a1,a1,s1
   12000051c:	df858028 	ld	a1,-32728\(gp\)
   120000520:	dca5076c 	ld	a1,1900\(a1\)
   120000524:	df858028 	ld	a1,-32728\(gp\)
   120000528:	dca50778 	ld	a1,1912\(a1\)
   12000052c:	df858028 	ld	a1,-32728\(gp\)
   120000530:	00b1282d 	daddu	a1,a1,s1
   120000534:	dca5076c 	ld	a1,1900\(a1\)
   120000538:	df858028 	ld	a1,-32728\(gp\)
   12000053c:	00b1282d 	daddu	a1,a1,s1
   120000540:	dca50778 	ld	a1,1912\(a1\)
   120000544:	df818028 	ld	at,-32728\(gp\)
   120000548:	0025082d 	daddu	at,at,a1
   12000054c:	dc25078e 	ld	a1,1934\(at\)
   120000550:	df818028 	ld	at,-32728\(gp\)
   120000554:	0025082d 	daddu	at,at,a1
   120000558:	fc2507a4 	sd	a1,1956\(at\)
   12000055c:	df818028 	ld	at,-32728\(gp\)
   120000560:	6421076c 	daddiu	at,at,1900
   120000564:	88250000 	lwl	a1,0\(at\)
   120000568:	98250003 	lwr	a1,3\(at\)
   12000056c:	df818028 	ld	at,-32728\(gp\)
   120000570:	64210778 	daddiu	at,at,1912
   120000574:	88250000 	lwl	a1,0\(at\)
   120000578:	98250003 	lwr	a1,3\(at\)
   12000057c:	df818028 	ld	at,-32728\(gp\)
   120000580:	6421076c 	daddiu	at,at,1900
   120000584:	0031082d 	daddu	at,at,s1
   120000588:	88250000 	lwl	a1,0\(at\)
   12000058c:	98250003 	lwr	a1,3\(at\)
   120000590:	df818028 	ld	at,-32728\(gp\)
   120000594:	64210778 	daddiu	at,at,1912
   120000598:	0031082d 	daddu	at,at,s1
   12000059c:	88250000 	lwl	a1,0\(at\)
   1200005a0:	98250003 	lwr	a1,3\(at\)
   1200005a4:	df818028 	ld	at,-32728\(gp\)
   1200005a8:	6421078e 	daddiu	at,at,1934
   1200005ac:	0025082d 	daddu	at,at,a1
   1200005b0:	88250000 	lwl	a1,0\(at\)
   1200005b4:	98250003 	lwr	a1,3\(at\)
   1200005b8:	df818028 	ld	at,-32728\(gp\)
   1200005bc:	642107a4 	daddiu	at,at,1956
   1200005c0:	0025082d 	daddu	at,at,a1
   1200005c4:	a8250000 	swl	a1,0\(at\)
   1200005c8:	b8250003 	swr	a1,3\(at\)
   1200005cc:	3c050000 	lui	a1,0x0
   1200005d0:	00bc282d 	daddu	a1,a1,gp
   1200005d4:	dca58050 	ld	a1,-32688\(a1\)
   1200005d8:	df858040 	ld	a1,-32704\(gp\)
   1200005dc:	64a506b0 	daddiu	a1,a1,1712
   1200005e0:	3c190000 	lui	t9,0x0
   1200005e4:	033cc82d 	daddu	t9,t9,gp
   1200005e8:	df398050 	ld	t9,-32688\(t9\)
   1200005ec:	df998040 	ld	t9,-32704\(gp\)
   1200005f0:	673906b0 	daddiu	t9,t9,1712
   1200005f4:	3c190000 	lui	t9,0x0
   1200005f8:	033cc82d 	daddu	t9,t9,gp
   1200005fc:	df398050 	ld	t9,-32688\(t9\)
   120000600:	0411002b 	bal	1200006b0 <fn2>
   120000604:	00000000 	nop
   120000608:	df998040 	ld	t9,-32704\(gp\)
   12000060c:	673906b0 	daddiu	t9,t9,1712
   120000610:	04110027 	bal	1200006b0 <fn2>
   120000614:	00000000 	nop
   120000618:	3c050000 	lui	a1,0x0
   12000061c:	00bc282d 	daddu	a1,a1,gp
   120000620:	dca58020 	ld	a1,-32736\(a1\)
   120000624:	1000fea2 	b	1200000b0 <fn>
   120000628:	00000000 	nop
   12000062c:	3c050000 	lui	a1,0x0
   120000630:	00bc282d 	daddu	a1,a1,gp
   120000634:	dca58048 	ld	a1,-32696\(a1\)
   120000638:	dca50000 	ld	a1,0\(a1\)
   12000063c:	1000001c 	b	1200006b0 <fn2>
   120000640:	00000000 	nop
   120000644:	df858028 	ld	a1,-32728\(gp\)
   120000648:	64a506f4 	daddiu	a1,a1,1780
   12000064c:	1000fe98 	b	1200000b0 <fn>
   120000650:	00000000 	nop
   120000654:	df858028 	ld	a1,-32728\(gp\)
   120000658:	64a50778 	daddiu	a1,a1,1912
   12000065c:	10000014 	b	1200006b0 <fn2>
   120000660:	00000000 	nop
   120000664:	df858030 	ld	a1,-32720\(gp\)
   120000668:	64a5e934 	daddiu	a1,a1,-5836
   12000066c:	1000fe90 	b	1200000b0 <fn>
   120000670:	00000000 	nop
   120000674:	df858028 	ld	a1,-32728\(gp\)
   120000678:	dca5076c 	ld	a1,1900\(a1\)
   12000067c:	1000000c 	b	1200006b0 <fn2>
   120000680:	00000000 	nop
   120000684:	df858028 	ld	a1,-32728\(gp\)
   120000688:	dca50700 	ld	a1,1792\(a1\)
   12000068c:	1000fe88 	b	1200000b0 <fn>
   120000690:	00000000 	nop
   120000694:	df818028 	ld	at,-32728\(gp\)
   120000698:	0025082d 	daddu	at,at,a1
   12000069c:	dc25078e 	ld	a1,1934\(at\)
   1200006a0:	10000003 	b	1200006b0 <fn2>
   1200006a4:	00000000 	nop
	\.\.\.

00000001200006b0 <fn2>:
	\.\.\.

Disassembly of section \.data:

00000001200106b8 <_fdata>:
	\.\.\.

00000001200106f4 <dg1>:
	\.\.\.

0000000120010730 <sp2>:
	\.\.\.

000000012001076c <dg2>:
	\.\.\.

Disassembly of section \.got:

00000001200107b0 <_GLOBAL_OFFSET_TABLE_>:
	\.\.\.
   1200107b8:	80000000 	.*
   1200107bc:	00000000 	.*
   1200107c0:	00000001 	.*
   1200107c4:	200106f4 	.*
   1200107c8:	00000001 	.*
   1200107cc:	20010000 	.*
   1200107d0:	00000001 	.*
   1200107d4:	20030000 	.*
   1200107d8:	00000001 	.*
   1200107dc:	200000b0 	.*
   1200107e0:	00000001 	.*
   1200107e4:	20000000 	.*
   1200107e8:	00000001 	.*
   1200107ec:	2001076c 	.*
   1200107f0:	00000001 	.*
   1200107f4:	200006b0 	.*
	\.\.\.
#pass
