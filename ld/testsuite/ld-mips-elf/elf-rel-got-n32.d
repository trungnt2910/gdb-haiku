#name: MIPS ELF got reloc n32
#as: -EB -n32 -KPIC
#source: ../../../gas/testsuite/gas/mips/elf-rel-got-n32.s
#ld:
#objdump: -D --show-raw-insn

.*: +file format elf32-n.*mips.*

Disassembly of section \.reginfo:

10000098 <\.reginfo>:
10000098:	92020022 	.*
	\.\.\.
100000ac:	100185a0 	.*

Disassembly of section \.text:

100000b0 <fn>:
100000b0:	8f858018 	lw	a1,-32744\(gp\)
100000b4:	8f858018 	lw	a1,-32744\(gp\)
100000b8:	24a5000c 	addiu	a1,a1,12
100000bc:	8f858018 	lw	a1,-32744\(gp\)
100000c0:	3c010001 	lui	at,0x1
100000c4:	3421e240 	ori	at,at,0xe240
100000c8:	00a12821 	addu	a1,a1,at
100000cc:	8f858018 	lw	a1,-32744\(gp\)
100000d0:	00b12821 	addu	a1,a1,s1
100000d4:	8f858018 	lw	a1,-32744\(gp\)
100000d8:	24a5000c 	addiu	a1,a1,12
100000dc:	00b12821 	addu	a1,a1,s1
100000e0:	8f858018 	lw	a1,-32744\(gp\)
100000e4:	3c010001 	lui	at,0x1
100000e8:	3421e240 	ori	at,at,0xe240
100000ec:	00a12821 	addu	a1,a1,at
100000f0:	00b12821 	addu	a1,a1,s1
100000f4:	8f85801c 	lw	a1,-32740\(gp\)
100000f8:	8ca504fc 	lw	a1,1276\(a1\)
100000fc:	8f85801c 	lw	a1,-32740\(gp\)
10000100:	8ca50508 	lw	a1,1288\(a1\)
10000104:	8f85801c 	lw	a1,-32740\(gp\)
10000108:	00b12821 	addu	a1,a1,s1
1000010c:	8ca504fc 	lw	a1,1276\(a1\)
10000110:	8f85801c 	lw	a1,-32740\(gp\)
10000114:	00b12821 	addu	a1,a1,s1
10000118:	8ca50508 	lw	a1,1288\(a1\)
1000011c:	8f81801c 	lw	at,-32740\(gp\)
10000120:	00250821 	addu	at,at,a1
10000124:	8c25051e 	lw	a1,1310\(at\)
10000128:	8f81801c 	lw	at,-32740\(gp\)
1000012c:	00250821 	addu	at,at,a1
10000130:	ac250534 	sw	a1,1332\(at\)
10000134:	8f818018 	lw	at,-32744\(gp\)
10000138:	88250000 	lwl	a1,0\(at\)
1000013c:	98250003 	lwr	a1,3\(at\)
10000140:	8f818018 	lw	at,-32744\(gp\)
10000144:	2421000c 	addiu	at,at,12
10000148:	88250000 	lwl	a1,0\(at\)
1000014c:	98250003 	lwr	a1,3\(at\)
10000150:	8f818018 	lw	at,-32744\(gp\)
10000154:	00310821 	addu	at,at,s1
10000158:	88250000 	lwl	a1,0\(at\)
1000015c:	98250003 	lwr	a1,3\(at\)
10000160:	8f818018 	lw	at,-32744\(gp\)
10000164:	2421000c 	addiu	at,at,12
10000168:	00310821 	addu	at,at,s1
1000016c:	88250000 	lwl	a1,0\(at\)
10000170:	98250003 	lwr	a1,3\(at\)
10000174:	8f818018 	lw	at,-32744\(gp\)
10000178:	24210022 	addiu	at,at,34
1000017c:	00250821 	addu	at,at,a1
10000180:	88250000 	lwl	a1,0\(at\)
10000184:	98250003 	lwr	a1,3\(at\)
10000188:	8f818018 	lw	at,-32744\(gp\)
1000018c:	24210038 	addiu	at,at,56
10000190:	00250821 	addu	at,at,a1
10000194:	a8250000 	swl	a1,0\(at\)
10000198:	b8250003 	swr	a1,3\(at\)
1000019c:	8f858018 	lw	a1,-32744\(gp\)
100001a0:	8f858020 	lw	a1,-32736\(gp\)
100001a4:	8f858024 	lw	a1,-32732\(gp\)
100001a8:	8f858018 	lw	a1,-32744\(gp\)
100001ac:	00b12821 	addu	a1,a1,s1
100001b0:	8f858020 	lw	a1,-32736\(gp\)
100001b4:	00b12821 	addu	a1,a1,s1
100001b8:	8f858024 	lw	a1,-32732\(gp\)
100001bc:	00b12821 	addu	a1,a1,s1
100001c0:	8f85801c 	lw	a1,-32740\(gp\)
100001c4:	8ca504fc 	lw	a1,1276\(a1\)
100001c8:	8f85801c 	lw	a1,-32740\(gp\)
100001cc:	8ca50508 	lw	a1,1288\(a1\)
100001d0:	8f85801c 	lw	a1,-32740\(gp\)
100001d4:	00b12821 	addu	a1,a1,s1
100001d8:	8ca504fc 	lw	a1,1276\(a1\)
100001dc:	8f85801c 	lw	a1,-32740\(gp\)
100001e0:	00b12821 	addu	a1,a1,s1
100001e4:	8ca50508 	lw	a1,1288\(a1\)
100001e8:	8f81801c 	lw	at,-32740\(gp\)
100001ec:	00250821 	addu	at,at,a1
100001f0:	8c25051e 	lw	a1,1310\(at\)
100001f4:	8f81801c 	lw	at,-32740\(gp\)
100001f8:	00250821 	addu	at,at,a1
100001fc:	ac250534 	sw	a1,1332\(at\)
10000200:	8f818018 	lw	at,-32744\(gp\)
10000204:	88250000 	lwl	a1,0\(at\)
10000208:	98250003 	lwr	a1,3\(at\)
1000020c:	8f818020 	lw	at,-32736\(gp\)
10000210:	88250000 	lwl	a1,0\(at\)
10000214:	98250003 	lwr	a1,3\(at\)
10000218:	8f818018 	lw	at,-32744\(gp\)
1000021c:	00310821 	addu	at,at,s1
10000220:	88250000 	lwl	a1,0\(at\)
10000224:	98250003 	lwr	a1,3\(at\)
10000228:	8f818020 	lw	at,-32736\(gp\)
1000022c:	00310821 	addu	at,at,s1
10000230:	88250000 	lwl	a1,0\(at\)
10000234:	98250003 	lwr	a1,3\(at\)
10000238:	8f818028 	lw	at,-32728\(gp\)
1000023c:	00250821 	addu	at,at,a1
10000240:	88250000 	lwl	a1,0\(at\)
10000244:	98250003 	lwr	a1,3\(at\)
10000248:	8f81802c 	lw	at,-32724\(gp\)
1000024c:	00250821 	addu	at,at,a1
10000250:	a8250000 	swl	a1,0\(at\)
10000254:	b8250003 	swr	a1,3\(at\)
10000258:	8f858030 	lw	a1,-32720\(gp\)
1000025c:	8f858030 	lw	a1,-32720\(gp\)
10000260:	8f998030 	lw	t9,-32720\(gp\)
10000264:	8f998030 	lw	t9,-32720\(gp\)
10000268:	8f998030 	lw	t9,-32720\(gp\)
1000026c:	0411ff90 	bal	100000b0 <fn>
10000270:	00000000 	nop
10000274:	8f998030 	lw	t9,-32720\(gp\)
10000278:	0411ff8d 	bal	100000b0 <fn>
1000027c:	00000000 	nop
10000280:	8f858034 	lw	a1,-32716\(gp\)
10000284:	8f858034 	lw	a1,-32716\(gp\)
10000288:	24a5000c 	addiu	a1,a1,12
1000028c:	8f858034 	lw	a1,-32716\(gp\)
10000290:	3c010001 	lui	at,0x1
10000294:	3421e240 	ori	at,at,0xe240
10000298:	00a12821 	addu	a1,a1,at
1000029c:	8f858034 	lw	a1,-32716\(gp\)
100002a0:	00b12821 	addu	a1,a1,s1
100002a4:	8f858034 	lw	a1,-32716\(gp\)
100002a8:	24a5000c 	addiu	a1,a1,12
100002ac:	00b12821 	addu	a1,a1,s1
100002b0:	8f858034 	lw	a1,-32716\(gp\)
100002b4:	3c010001 	lui	at,0x1
100002b8:	3421e240 	ori	at,at,0xe240
100002bc:	00a12821 	addu	a1,a1,at
100002c0:	00b12821 	addu	a1,a1,s1
100002c4:	8f85801c 	lw	a1,-32740\(gp\)
100002c8:	8ca50574 	lw	a1,1396\(a1\)
100002cc:	8f85801c 	lw	a1,-32740\(gp\)
100002d0:	8ca50580 	lw	a1,1408\(a1\)
100002d4:	8f85801c 	lw	a1,-32740\(gp\)
100002d8:	00b12821 	addu	a1,a1,s1
100002dc:	8ca50574 	lw	a1,1396\(a1\)
100002e0:	8f85801c 	lw	a1,-32740\(gp\)
100002e4:	00b12821 	addu	a1,a1,s1
100002e8:	8ca50580 	lw	a1,1408\(a1\)
100002ec:	8f81801c 	lw	at,-32740\(gp\)
100002f0:	00250821 	addu	at,at,a1
100002f4:	8c250596 	lw	a1,1430\(at\)
100002f8:	8f81801c 	lw	at,-32740\(gp\)
100002fc:	00250821 	addu	at,at,a1
10000300:	ac2505ac 	sw	a1,1452\(at\)
10000304:	8f818034 	lw	at,-32716\(gp\)
10000308:	88250000 	lwl	a1,0\(at\)
1000030c:	98250003 	lwr	a1,3\(at\)
10000310:	8f818034 	lw	at,-32716\(gp\)
10000314:	2421000c 	addiu	at,at,12
10000318:	88250000 	lwl	a1,0\(at\)
1000031c:	98250003 	lwr	a1,3\(at\)
10000320:	8f818034 	lw	at,-32716\(gp\)
10000324:	00310821 	addu	at,at,s1
10000328:	88250000 	lwl	a1,0\(at\)
1000032c:	98250003 	lwr	a1,3\(at\)
10000330:	8f818034 	lw	at,-32716\(gp\)
10000334:	2421000c 	addiu	at,at,12
10000338:	00310821 	addu	at,at,s1
1000033c:	88250000 	lwl	a1,0\(at\)
10000340:	98250003 	lwr	a1,3\(at\)
10000344:	8f818034 	lw	at,-32716\(gp\)
10000348:	24210022 	addiu	at,at,34
1000034c:	00250821 	addu	at,at,a1
10000350:	88250000 	lwl	a1,0\(at\)
10000354:	98250003 	lwr	a1,3\(at\)
10000358:	8f818034 	lw	at,-32716\(gp\)
1000035c:	24210038 	addiu	at,at,56
10000360:	00250821 	addu	at,at,a1
10000364:	a8250000 	swl	a1,0\(at\)
10000368:	b8250003 	swr	a1,3\(at\)
1000036c:	8f858034 	lw	a1,-32716\(gp\)
10000370:	8f858038 	lw	a1,-32712\(gp\)
10000374:	8f85803c 	lw	a1,-32708\(gp\)
10000378:	8f858034 	lw	a1,-32716\(gp\)
1000037c:	00b12821 	addu	a1,a1,s1
10000380:	8f858038 	lw	a1,-32712\(gp\)
10000384:	00b12821 	addu	a1,a1,s1
10000388:	8f85803c 	lw	a1,-32708\(gp\)
1000038c:	00b12821 	addu	a1,a1,s1
10000390:	8f85801c 	lw	a1,-32740\(gp\)
10000394:	8ca50574 	lw	a1,1396\(a1\)
10000398:	8f85801c 	lw	a1,-32740\(gp\)
1000039c:	8ca50580 	lw	a1,1408\(a1\)
100003a0:	8f85801c 	lw	a1,-32740\(gp\)
100003a4:	00b12821 	addu	a1,a1,s1
100003a8:	8ca50574 	lw	a1,1396\(a1\)
100003ac:	8f85801c 	lw	a1,-32740\(gp\)
100003b0:	00b12821 	addu	a1,a1,s1
100003b4:	8ca50580 	lw	a1,1408\(a1\)
100003b8:	8f81801c 	lw	at,-32740\(gp\)
100003bc:	00250821 	addu	at,at,a1
100003c0:	8c250596 	lw	a1,1430\(at\)
100003c4:	8f81801c 	lw	at,-32740\(gp\)
100003c8:	00250821 	addu	at,at,a1
100003cc:	ac2505ac 	sw	a1,1452\(at\)
100003d0:	8f818034 	lw	at,-32716\(gp\)
100003d4:	88250000 	lwl	a1,0\(at\)
100003d8:	98250003 	lwr	a1,3\(at\)
100003dc:	8f818038 	lw	at,-32712\(gp\)
100003e0:	88250000 	lwl	a1,0\(at\)
100003e4:	98250003 	lwr	a1,3\(at\)
100003e8:	8f818034 	lw	at,-32716\(gp\)
100003ec:	00310821 	addu	at,at,s1
100003f0:	88250000 	lwl	a1,0\(at\)
100003f4:	98250003 	lwr	a1,3\(at\)
100003f8:	8f818038 	lw	at,-32712\(gp\)
100003fc:	00310821 	addu	at,at,s1
10000400:	88250000 	lwl	a1,0\(at\)
10000404:	98250003 	lwr	a1,3\(at\)
10000408:	8f818040 	lw	at,-32704\(gp\)
1000040c:	00250821 	addu	at,at,a1
10000410:	88250000 	lwl	a1,0\(at\)
10000414:	98250003 	lwr	a1,3\(at\)
10000418:	8f818044 	lw	at,-32700\(gp\)
1000041c:	00250821 	addu	at,at,a1
10000420:	a8250000 	swl	a1,0\(at\)
10000424:	b8250003 	swr	a1,3\(at\)
10000428:	8f858048 	lw	a1,-32696\(gp\)
1000042c:	8f858048 	lw	a1,-32696\(gp\)
10000430:	8f998048 	lw	t9,-32696\(gp\)
10000434:	8f998048 	lw	t9,-32696\(gp\)
10000438:	8f998048 	lw	t9,-32696\(gp\)
1000043c:	0411001d 	bal	100004b4 <fn2>
10000440:	00000000 	nop
10000444:	8f998048 	lw	t9,-32696\(gp\)
10000448:	0411001a 	bal	100004b4 <fn2>
1000044c:	00000000 	nop
10000450:	1000ff17 	b	100000b0 <fn>
10000454:	8f858018 	lw	a1,-32744\(gp\)
10000458:	8f85801c 	lw	a1,-32740\(gp\)
1000045c:	10000015 	b	100004b4 <fn2>
10000460:	8ca50574 	lw	a1,1396\(a1\)
10000464:	1000ff12 	b	100000b0 <fn>
10000468:	8f858018 	lw	a1,-32744\(gp\)
1000046c:	8f858038 	lw	a1,-32712\(gp\)
10000470:	10000010 	b	100004b4 <fn2>
10000474:	00000000 	nop
10000478:	8f858024 	lw	a1,-32732\(gp\)
1000047c:	1000ff0c 	b	100000b0 <fn>
10000480:	00000000 	nop
10000484:	8f85801c 	lw	a1,-32740\(gp\)
10000488:	1000000a 	b	100004b4 <fn2>
1000048c:	8ca50574 	lw	a1,1396\(a1\)
10000490:	8f85801c 	lw	a1,-32740\(gp\)
10000494:	1000ff06 	b	100000b0 <fn>
10000498:	8ca50508 	lw	a1,1288\(a1\)
1000049c:	8f81801c 	lw	at,-32740\(gp\)
100004a0:	00250821 	addu	at,at,a1
100004a4:	10000003 	b	100004b4 <fn2>
100004a8:	8c250596 	lw	a1,1430\(at\)
	\.\.\.

100004b4 <fn2>:
	\.\.\.
Disassembly of section \.data:

100104c0 <_fdata>:
	\.\.\.

100104fc <dg1>:
	\.\.\.

10010538 <sp2>:
	\.\.\.

10010574 <dg2>:
	\.\.\.
Disassembly of section \.got:

100105b0 <_GLOBAL_OFFSET_TABLE_>:
100105b0:	00000000 	.*
100105b4:	80000000 	.*
100105b8:	100104fc 	.*
100105bc:	10010000 	.*
100105c0:	10010508 	.*
100105c4:	1002e73c 	.*
100105c8:	1001051e 	.*
100105cc:	10010534 	.*
100105d0:	100000b0 	.*
100105d4:	10010574 	.*
100105d8:	10010580 	.*
100105dc:	1002e7b4 	.*
100105e0:	10010596 	.*
100105e4:	100105ac 	.*
100105e8:	100004b4 	.*
100105ec:	00000000 	.*
	\.\.\.
#pass
