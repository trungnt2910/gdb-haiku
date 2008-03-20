#name: MIPS ELF got reloc n64
#as: -EB -64 -KPIC
#source: ../../../gas/testsuite/gas/mips/elf-rel-got-n64.s
#ld: -melf64btsmip
#objdump: -D --show-raw-insn

.*: +file format elf64-.*mips.*

Disassembly of section \.MIPS\.options:

00000000100000b0 <\.MIPS\.options>:
    100000b0:	01280000 	.*
    100000b4:	00000000 	.*
    100000b8:	92020022 	.*
	\.\.\.
    100000d4:	101085d0 	.*
Disassembly of section \.text:

00000000100000e0 <fn>:
    100000e0:	df8580b8 	ld	a1,-32584\(gp\)
    100000e4:	df8580b8 	ld	a1,-32584\(gp\)
    100000e8:	64a5000c 	daddiu	a1,a1,12
    100000ec:	df8580b8 	ld	a1,-32584\(gp\)
    100000f0:	3c010002 	lui	at,0x2
    100000f4:	6421e240 	daddiu	at,at,-7616
    100000f8:	00a1282d 	daddu	a1,a1,at
    100000fc:	df8580b8 	ld	a1,-32584\(gp\)
    10000100:	00b1282d 	daddu	a1,a1,s1
    10000104:	df8580b8 	ld	a1,-32584\(gp\)
    10000108:	64a5000c 	daddiu	a1,a1,12
    1000010c:	00b1282d 	daddu	a1,a1,s1
    10000110:	df8580b8 	ld	a1,-32584\(gp\)
    10000114:	3c010002 	lui	at,0x2
    10000118:	6421e240 	daddiu	at,at,-7616
    1000011c:	00a1282d 	daddu	a1,a1,at
    10000120:	00b1282d 	daddu	a1,a1,s1
    10000124:	df8580b8 	ld	a1,-32584\(gp\)
    10000128:	dca50000 	ld	a1,0\(a1\)
    1000012c:	df8580b8 	ld	a1,-32584\(gp\)
    10000130:	dca5000c 	ld	a1,12\(a1\)
    10000134:	df8580b8 	ld	a1,-32584\(gp\)
    10000138:	00b1282d 	daddu	a1,a1,s1
    1000013c:	dca50000 	ld	a1,0\(a1\)
    10000140:	df8580b8 	ld	a1,-32584\(gp\)
    10000144:	00b1282d 	daddu	a1,a1,s1
    10000148:	dca5000c 	ld	a1,12\(a1\)
    1000014c:	df8180b8 	ld	at,-32584\(gp\)
    10000150:	0025082d 	daddu	at,at,a1
    10000154:	dc250022 	ld	a1,34\(at\)
    10000158:	df8180b8 	ld	at,-32584\(gp\)
    1000015c:	0025082d 	daddu	at,at,a1
    10000160:	fc250038 	sd	a1,56\(at\)
    10000164:	df8180b8 	ld	at,-32584\(gp\)
    10000168:	88250000 	lwl	a1,0\(at\)
    1000016c:	98250003 	lwr	a1,3\(at\)
    10000170:	df8180b8 	ld	at,-32584\(gp\)
    10000174:	6421000c 	daddiu	at,at,12
    10000178:	88250000 	lwl	a1,0\(at\)
    1000017c:	98250003 	lwr	a1,3\(at\)
    10000180:	df8180b8 	ld	at,-32584\(gp\)
    10000184:	0031082d 	daddu	at,at,s1
    10000188:	88250000 	lwl	a1,0\(at\)
    1000018c:	98250003 	lwr	a1,3\(at\)
    10000190:	df8180b8 	ld	at,-32584\(gp\)
    10000194:	6421000c 	daddiu	at,at,12
    10000198:	0031082d 	daddu	at,at,s1
    1000019c:	88250000 	lwl	a1,0\(at\)
    100001a0:	98250003 	lwr	a1,3\(at\)
    100001a4:	df8180b8 	ld	at,-32584\(gp\)
    100001a8:	64210022 	daddiu	at,at,34
    100001ac:	0025082d 	daddu	at,at,a1
    100001b0:	88250000 	lwl	a1,0\(at\)
    100001b4:	98250003 	lwr	a1,3\(at\)
    100001b8:	df8180b8 	ld	at,-32584\(gp\)
    100001bc:	64210038 	daddiu	at,at,56
    100001c0:	0025082d 	daddu	at,at,a1
    100001c4:	a8250000 	swl	a1,0\(at\)
    100001c8:	b8250003 	swr	a1,3\(at\)
    100001cc:	df858020 	ld	a1,-32736\(gp\)
    100001d0:	df858028 	ld	a1,-32728\(gp\)
    100001d4:	df858030 	ld	a1,-32720\(gp\)
    100001d8:	df858020 	ld	a1,-32736\(gp\)
    100001dc:	00b1282d 	daddu	a1,a1,s1
    100001e0:	df858028 	ld	a1,-32728\(gp\)
    100001e4:	00b1282d 	daddu	a1,a1,s1
    100001e8:	df858030 	ld	a1,-32720\(gp\)
    100001ec:	00b1282d 	daddu	a1,a1,s1
    100001f0:	df858038 	ld	a1,-32712\(gp\)
    100001f4:	dca5052c 	ld	a1,1324\(a1\)
    100001f8:	df858038 	ld	a1,-32712\(gp\)
    100001fc:	dca50538 	ld	a1,1336\(a1\)
    10000200:	df858038 	ld	a1,-32712\(gp\)
    10000204:	00b1282d 	daddu	a1,a1,s1
    10000208:	dca5052c 	ld	a1,1324\(a1\)
    1000020c:	df858038 	ld	a1,-32712\(gp\)
    10000210:	00b1282d 	daddu	a1,a1,s1
    10000214:	dca50538 	ld	a1,1336\(a1\)
    10000218:	df818038 	ld	at,-32712\(gp\)
    1000021c:	0025082d 	daddu	at,at,a1
    10000220:	dc25054e 	ld	a1,1358\(at\)
    10000224:	df818038 	ld	at,-32712\(gp\)
    10000228:	0025082d 	daddu	at,at,a1
    1000022c:	fc250564 	sd	a1,1380\(at\)
    10000230:	df818020 	ld	at,-32736\(gp\)
    10000234:	88250000 	lwl	a1,0\(at\)
    10000238:	98250003 	lwr	a1,3\(at\)
    1000023c:	df818028 	ld	at,-32728\(gp\)
    10000240:	88250000 	lwl	a1,0\(at\)
    10000244:	98250003 	lwr	a1,3\(at\)
    10000248:	df818020 	ld	at,-32736\(gp\)
    1000024c:	0031082d 	daddu	at,at,s1
    10000250:	88250000 	lwl	a1,0\(at\)
    10000254:	98250003 	lwr	a1,3\(at\)
    10000258:	df818028 	ld	at,-32728\(gp\)
    1000025c:	0031082d 	daddu	at,at,s1
    10000260:	88250000 	lwl	a1,0\(at\)
    10000264:	98250003 	lwr	a1,3\(at\)
    10000268:	df818040 	ld	at,-32704\(gp\)
    1000026c:	0025082d 	daddu	at,at,a1
    10000270:	88250000 	lwl	a1,0\(at\)
    10000274:	98250003 	lwr	a1,3\(at\)
    10000278:	df818048 	ld	at,-32696\(gp\)
    1000027c:	0025082d 	daddu	at,at,a1
    10000280:	a8250000 	swl	a1,0\(at\)
    10000284:	b8250003 	swr	a1,3\(at\)
    10000288:	df8580a8 	ld	a1,-32600\(gp\)
    1000028c:	df858050 	ld	a1,-32688\(gp\)
    10000290:	df9980a8 	ld	t9,-32600\(gp\)
    10000294:	df998050 	ld	t9,-32688\(gp\)
    10000298:	df9980a8 	ld	t9,-32600\(gp\)
    1000029c:	0320f809 	jalr	t9
    100002a0:	00000000 	nop
    100002a4:	df998050 	ld	t9,-32688\(gp\)
    100002a8:	0320f809 	jalr	t9
    100002ac:	00000000 	nop
    100002b0:	df8580c0 	ld	a1,-32576\(gp\)
    100002b4:	df8580c0 	ld	a1,-32576\(gp\)
    100002b8:	64a5000c 	daddiu	a1,a1,12
    100002bc:	df8580c0 	ld	a1,-32576\(gp\)
    100002c0:	3c010002 	lui	at,0x2
    100002c4:	6421e240 	daddiu	at,at,-7616
    100002c8:	00a1282d 	daddu	a1,a1,at
    100002cc:	df8580c0 	ld	a1,-32576\(gp\)
    100002d0:	00b1282d 	daddu	a1,a1,s1
    100002d4:	df8580c0 	ld	a1,-32576\(gp\)
    100002d8:	64a5000c 	daddiu	a1,a1,12
    100002dc:	00b1282d 	daddu	a1,a1,s1
    100002e0:	df8580c0 	ld	a1,-32576\(gp\)
    100002e4:	3c010002 	lui	at,0x2
    100002e8:	6421e240 	daddiu	at,at,-7616
    100002ec:	00a1282d 	daddu	a1,a1,at
    100002f0:	00b1282d 	daddu	a1,a1,s1
    100002f4:	df8580c0 	ld	a1,-32576\(gp\)
    100002f8:	dca50000 	ld	a1,0\(a1\)
    100002fc:	df8580c0 	ld	a1,-32576\(gp\)
    10000300:	dca5000c 	ld	a1,12\(a1\)
    10000304:	df8580c0 	ld	a1,-32576\(gp\)
    10000308:	00b1282d 	daddu	a1,a1,s1
    1000030c:	dca50000 	ld	a1,0\(a1\)
    10000310:	df8580c0 	ld	a1,-32576\(gp\)
    10000314:	00b1282d 	daddu	a1,a1,s1
    10000318:	dca5000c 	ld	a1,12\(a1\)
    1000031c:	df8180c0 	ld	at,-32576\(gp\)
    10000320:	0025082d 	daddu	at,at,a1
    10000324:	dc250022 	ld	a1,34\(at\)
    10000328:	df8180c0 	ld	at,-32576\(gp\)
    1000032c:	0025082d 	daddu	at,at,a1
    10000330:	fc250038 	sd	a1,56\(at\)
    10000334:	df8180c0 	ld	at,-32576\(gp\)
    10000338:	88250000 	lwl	a1,0\(at\)
    1000033c:	98250003 	lwr	a1,3\(at\)
    10000340:	df8180c0 	ld	at,-32576\(gp\)
    10000344:	6421000c 	daddiu	at,at,12
    10000348:	88250000 	lwl	a1,0\(at\)
    1000034c:	98250003 	lwr	a1,3\(at\)
    10000350:	df8180c0 	ld	at,-32576\(gp\)
    10000354:	0031082d 	daddu	at,at,s1
    10000358:	88250000 	lwl	a1,0\(at\)
    1000035c:	98250003 	lwr	a1,3\(at\)
    10000360:	df8180c0 	ld	at,-32576\(gp\)
    10000364:	6421000c 	daddiu	at,at,12
    10000368:	0031082d 	daddu	at,at,s1
    1000036c:	88250000 	lwl	a1,0\(at\)
    10000370:	98250003 	lwr	a1,3\(at\)
    10000374:	df8180c0 	ld	at,-32576\(gp\)
    10000378:	64210022 	daddiu	at,at,34
    1000037c:	0025082d 	daddu	at,at,a1
    10000380:	88250000 	lwl	a1,0\(at\)
    10000384:	98250003 	lwr	a1,3\(at\)
    10000388:	df8180c0 	ld	at,-32576\(gp\)
    1000038c:	64210038 	daddiu	at,at,56
    10000390:	0025082d 	daddu	at,at,a1
    10000394:	a8250000 	swl	a1,0\(at\)
    10000398:	b8250003 	swr	a1,3\(at\)
    1000039c:	df858058 	ld	a1,-32680\(gp\)
    100003a0:	df858060 	ld	a1,-32672\(gp\)
    100003a4:	df858068 	ld	a1,-32664\(gp\)
    100003a8:	df858058 	ld	a1,-32680\(gp\)
    100003ac:	00b1282d 	daddu	a1,a1,s1
    100003b0:	df858060 	ld	a1,-32672\(gp\)
    100003b4:	00b1282d 	daddu	a1,a1,s1
    100003b8:	df858068 	ld	a1,-32664\(gp\)
    100003bc:	00b1282d 	daddu	a1,a1,s1
    100003c0:	df858038 	ld	a1,-32712\(gp\)
    100003c4:	dca505a4 	ld	a1,1444\(a1\)
    100003c8:	df858038 	ld	a1,-32712\(gp\)
    100003cc:	dca505b0 	ld	a1,1456\(a1\)
    100003d0:	df858038 	ld	a1,-32712\(gp\)
    100003d4:	00b1282d 	daddu	a1,a1,s1
    100003d8:	dca505a4 	ld	a1,1444\(a1\)
    100003dc:	df858038 	ld	a1,-32712\(gp\)
    100003e0:	00b1282d 	daddu	a1,a1,s1
    100003e4:	dca505b0 	ld	a1,1456\(a1\)
    100003e8:	df818038 	ld	at,-32712\(gp\)
    100003ec:	0025082d 	daddu	at,at,a1
    100003f0:	dc2505c6 	ld	a1,1478\(at\)
    100003f4:	df818038 	ld	at,-32712\(gp\)
    100003f8:	0025082d 	daddu	at,at,a1
    100003fc:	fc2505dc 	sd	a1,1500\(at\)
    10000400:	df818058 	ld	at,-32680\(gp\)
    10000404:	88250000 	lwl	a1,0\(at\)
    10000408:	98250003 	lwr	a1,3\(at\)
    1000040c:	df818060 	ld	at,-32672\(gp\)
    10000410:	88250000 	lwl	a1,0\(at\)
    10000414:	98250003 	lwr	a1,3\(at\)
    10000418:	df818058 	ld	at,-32680\(gp\)
    1000041c:	0031082d 	daddu	at,at,s1
    10000420:	88250000 	lwl	a1,0\(at\)
    10000424:	98250003 	lwr	a1,3\(at\)
    10000428:	df818060 	ld	at,-32672\(gp\)
    1000042c:	0031082d 	daddu	at,at,s1
    10000430:	88250000 	lwl	a1,0\(at\)
    10000434:	98250003 	lwr	a1,3\(at\)
    10000438:	df818070 	ld	at,-32656\(gp\)
    1000043c:	0025082d 	daddu	at,at,a1
    10000440:	88250000 	lwl	a1,0\(at\)
    10000444:	98250003 	lwr	a1,3\(at\)
    10000448:	df818078 	ld	at,-32648\(gp\)
    1000044c:	0025082d 	daddu	at,at,a1
    10000450:	a8250000 	swl	a1,0\(at\)
    10000454:	b8250003 	swr	a1,3\(at\)
    10000458:	df8580b0 	ld	a1,-32592\(gp\)
    1000045c:	df858080 	ld	a1,-32640\(gp\)
    10000460:	df9980b0 	ld	t9,-32592\(gp\)
    10000464:	df998080 	ld	t9,-32640\(gp\)
    10000468:	df9980b0 	ld	t9,-32592\(gp\)
    1000046c:	0320f809 	jalr	t9
    10000470:	00000000 	nop
    10000474:	df998080 	ld	t9,-32640\(gp\)
    10000478:	0320f809 	jalr	t9
    1000047c:	00000000 	nop
    10000480:	1000ff17 	b	100000e0 <fn>
    10000484:	df8580b8 	ld	a1,-32584\(gp\)
    10000488:	df8580c0 	ld	a1,-32576\(gp\)
    1000048c:	10000015 	b	100004e4 <fn2>
    10000490:	dca50000 	ld	a1,0\(a1\)
    10000494:	1000ff12 	b	100000e0 <fn>
    10000498:	df858020 	ld	a1,-32736\(gp\)
    1000049c:	df858060 	ld	a1,-32672\(gp\)
    100004a0:	10000010 	b	100004e4 <fn2>
    100004a4:	00000000 	nop
    100004a8:	df858030 	ld	a1,-32720\(gp\)
    100004ac:	1000ff0c 	b	100000e0 <fn>
    100004b0:	00000000 	nop
    100004b4:	df858038 	ld	a1,-32712\(gp\)
    100004b8:	1000000a 	b	100004e4 <fn2>
    100004bc:	dca505a4 	ld	a1,1444\(a1\)
    100004c0:	df858038 	ld	a1,-32712\(gp\)
    100004c4:	1000ff06 	b	100000e0 <fn>
    100004c8:	dca50538 	ld	a1,1336\(a1\)
    100004cc:	df818038 	ld	at,-32712\(gp\)
    100004d0:	0025082d 	daddu	at,at,a1
    100004d4:	10000003 	b	100004e4 <fn2>
    100004d8:	dc2505c6 	ld	a1,1478\(at\)
	\.\.\.

00000000100004e4 <fn2>:
	\.\.\.
Disassembly of section \.data:

00000000101004f0 <_fdata>:
	\.\.\.

000000001010052c <dg1>:
	\.\.\.

0000000010100568 <sp2>:
	\.\.\.

00000000101005a4 <dg2>:
	\.\.\.
Disassembly of section \.got:

00000000101005e0 <_GLOBAL_OFFSET_TABLE_>:
	\.\.\.
    101005e8:	80000000 	.*
    101005ec:	00000000 	.*
    101005f0:	00000000 	.*
    101005f4:	1010052c 	.*
    101005f8:	00000000 	.*
    101005fc:	10100538 	.*
    10100600:	00000000 	.*
    10100604:	1011e76c 	.*
    10100608:	00000000 	.*
    1010060c:	10100000 	.*
    10100610:	00000000 	.*
    10100614:	1010054e 	.*
    10100618:	00000000 	.*
    1010061c:	10100564 	.*
    10100620:	00000000 	.*
    10100624:	100000e0 	.*
    10100628:	00000000 	.*
    1010062c:	101005a4 	.*
    10100630:	00000000 	.*
    10100634:	101005b0 	.*
    10100638:	00000000 	.*
    1010063c:	1011e7e4 	.*
    10100640:	00000000 	.*
    10100644:	101005c6 	.*
    10100648:	00000000 	.*
    1010064c:	101005dc 	.*
    10100650:	00000000 	.*
    10100654:	100004e4 	.*
    10100658:	00000000 	.*
	\.\.\.
    1010067c:	100000e0 	.*
    10100680:	00000000 	.*
    10100684:	100004e4 	.*
    10100688:	00000000 	.*
    1010068c:	1010052c 	.*
    10100690:	00000000 	.*
    10100694:	101005a4 	.*
