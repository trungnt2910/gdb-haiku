#name: s390 opcode
#objdump: -drw

.*: +file format .*

Disassembly of section .text:

.* <foo>:
.*:	5a 65 af ff [	 ]*a	%r6,4095\(%r5,%r10\)
.*:	6a 65 af ff [	 ]*ad	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 1a [	 ]*adb	%f6,4095\(%r5,%r10\)
.*:	b3 1a 00 69 [	 ]*adbr	%f6,%f9
.*:	2a 69 [	 ]*adr	%f6,%f9
.*:	7a 65 af ff [	 ]*ae	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 0a [	 ]*aeb	%f6,4095\(%r5,%r10\)
.*:	b3 0a 00 69 [	 ]*aebr	%f6,%f9
.*:	3a 69 [	 ]*aer	%f6,%f9
.*:	4a 65 af ff [	 ]*ah	%r6,4095\(%r5,%r10\)
.*:	a7 6a 80 01 [	 ]*ahi	%r6,-32767
.*:	5e 65 af ff [	 ]*al	%r6,4095\(%r5,%r10\)
.*:	1e 69 [	 ]*alr	%r6,%r9
.*:	fa 58 5f ff af ff [	 ]*ap	4095\(6,%r5\),4095\(9,%r10\)
.*:	1a 69 [	 ]*ar	%r6,%r9
.*:	7e 65 af ff [	 ]*au	%f6,4095\(%r5,%r10\)
.*:	3e 69 [	 ]*aur	%f6,%f9
.*:	6e 65 af ff [	 ]*aw	%f6,4095\(%r5,%r10\)
.*:	2e 69 [	 ]*awr	%f6,%f9
.*:	b3 4a 00 69 [	 ]*axbr	%f6,%f9
.*:	36 69 [	 ]*axr	%f6,%f9
.*:	47 f5 af ff [	 ]*b	4095\(%r5,%r10\)
.*:	b2 40 00 69 [	 ]*bakr	%r6,%r9
.*:	45 65 af ff [	 ]*bal	%r6,4095\(%r5,%r10\)
.*:	05 69 [	 ]*balr	%r6,%r9
.*:	4d 65 af ff [	 ]*bas	%r6,4095\(%r5,%r10\)
.*:	0d 69 [	 ]*basr	%r6,%r9
.*:	0c 69 [	 ]*bassm	%r6,%r9
.*:	47 65 af ff [	 ]*blh	4095\(%r5,%r10\)
.*:	07 69 [	 ]*blhr	%r9
.*:	46 65 af ff [	 ]*bct	%r6,4095\(%r5,%r10\)
.*:	06 69 [	 ]*bctr	%r6,%r9
.*:	47 85 af ff [	 ]*be	4095\(%r5,%r10\)
.*:	07 89 [	 ]*ber	%r9
.*:	47 25 af ff [	 ]*bh	4095\(%r5,%r10\)
.*:	47 a5 af ff [	 ]*bhe	4095\(%r5,%r10\)
.*:	07 a9 [	 ]*bher	%r9
.*:	07 29 [	 ]*bhr	%r9
.*:	47 45 af ff [	 ]*bl	4095\(%r5,%r10\)
.*:	47 c5 af ff [	 ]*ble	4095\(%r5,%r10\)
.*:	07 c9 [	 ]*bler	%r9
.*:	47 65 af ff [	 ]*blh	4095\(%r5,%r10\)
.*:	07 69 [	 ]*blhr	%r9
.*:	07 49 [	 ]*blr	%r9
.*:	47 45 af ff [	 ]*bl	4095\(%r5,%r10\)
.*:	07 49 [	 ]*blr	%r9
.*:	47 75 af ff [	 ]*bne	4095\(%r5,%r10\)
.*:	07 79 [	 ]*bner	%r9
.*:	47 d5 af ff [	 ]*bnh	4095\(%r5,%r10\)
.*:	47 55 af ff [	 ]*bnhe	4095\(%r5,%r10\)
.*:	07 59 [	 ]*bnher	%r9
.*:	07 d9 [	 ]*bnhr	%r9
.*:	47 b5 af ff [	 ]*bnl	4095\(%r5,%r10\)
.*:	47 35 af ff [	 ]*bnle	4095\(%r5,%r10\)
.*:	07 39 [	 ]*bnler	%r9
.*:	47 95 af ff [	 ]*bnlh	4095\(%r5,%r10\)
.*:	07 99 [	 ]*bnlhr	%r9
.*:	07 b9 [	 ]*bnlr	%r9
.*:	47 b5 af ff [	 ]*bnl	4095\(%r5,%r10\)
.*:	07 b9 [	 ]*bnlr	%r9
.*:	47 e5 af ff [	 ]*bno	4095\(%r5,%r10\)
.*:	07 e9 [	 ]*bnor	%r9
.*:	47 d5 af ff [	 ]*bnh	4095\(%r5,%r10\)
.*:	07 d9 [	 ]*bnhr	%r9
.*:	47 75 af ff [	 ]*bne	4095\(%r5,%r10\)
.*:	07 79 [	 ]*bner	%r9
.*:	47 15 af ff [	 ]*bo	4095\(%r5,%r10\)
.*:	07 19 [	 ]*bor	%r9
.*:	47 25 af ff [	 ]*bh	4095\(%r5,%r10\)
.*:	07 29 [	 ]*bhr	%r9
.*:	07 f9 [	 ]*br	%r9
.*:	a7 95 00 00 [	 ]*bras	%r9,e2 <foo\+0xe2>
.*:	a7 64 00 00 [	 ]*jlh	e6 <foo\+0xe6>
.*:	a7 66 00 00 [	 ]*brct	%r6,ea <foo\+0xea>
.*:	84 69 00 00 [	 ]*brxh	%r6,%r9,ee <foo\+0xee>
.*:	85 69 00 00 [	 ]*brxle	%r6,%r9,f2 <foo\+0xf2>
.*:	b2 5a 00 69 [	 ]*bsa	%r6,%r9
.*:	b2 58 00 69 [	 ]*bsg	%r6,%r9
.*:	0b 69 [	 ]*bsm	%r6,%r9
.*:	86 69 5f ff [	 ]*bxh	%r6,%r9,4095\(%r5\)
.*:	87 69 5f ff [	 ]*bxle	%r6,%r9,4095\(%r5\)
.*:	47 85 af ff [	 ]*be	4095\(%r5,%r10\)
.*:	07 89 [	 ]*ber	%r9
.*:	59 65 af ff [	 ]*c	%r6,4095\(%r5,%r10\)
.*:	69 65 af ff [	 ]*cd	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 19 [	 ]*cdb	%f6,4095\(%r5,%r10\)
.*:	b3 19 00 69 [	 ]*cdbr	%f6,%f9
.*:	b3 95 00 69 [	 ]*cdfbr	%f6,%r9
.*:	b3 b5 00 69 [	 ]*cdfr	%f6,%r9
.*:	29 69 [	 ]*cdr	%f6,%f9
.*:	bb 69 5f ff [	 ]*cds	%r6,%r9,4095\(%r5\)
.*:	79 65 af ff [	 ]*ce	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 09 [	 ]*ceb	%f6,4095\(%r5,%r10\)
.*:	b3 09 00 69 [	 ]*cebr	%f6,%f9
.*:	b3 94 00 69 [	 ]*cefbr	%f6,%r9
.*:	b3 b4 00 69 [	 ]*cefr	%f6,%r9
.*:	39 69 [	 ]*cer	%f6,%f9
.*:	b2 1a 5f ff [	 ]*cfc	4095\(%r5\)
.*:	b3 99 50 69 [	 ]*cfdbr	%r6,5,%f9
.*:	b3 98 50 69 [	 ]*cfebr	%r6,5,%f9
.*:	b3 9a 50 69 [	 ]*cfxbr	%r6,5,%f9
.*:	49 65 af ff [	 ]*ch	%r6,4095\(%r5,%r10\)
.*:	a7 6e 80 01 [	 ]*chi	%r6,-32767
.*:	b2 41 00 69 [	 ]*cksm	%r6,%r9
.*:	55 65 af ff [	 ]*cl	%r6,4095\(%r5,%r10\)
.*:	d5 ff 5f ff af ff [	 ]*clc	4095\(256,%r5\),4095\(%r10\)
.*:	0f 69 [	 ]*clcl	%r6,%r9
.*:	a9 69 5f ff [	 ]*clcle	%r6,%r9,4095\(%r5\)
.*:	95 ff 5f ff [	 ]*cli	4095\(%r5\),255
.*:	bd 6a 5f ff [	 ]*clm	%r6,10,4095\(%r5\)
.*:	15 69 [	 ]*clr	%r6,%r9
.*:	b2 5d 00 69 [	 ]*clst	%r6,%r9
.*:	b2 63 00 69 [	 ]*cmpsc	%r6,%r9
.*:	f9 58 5f ff af ff [	 ]*cp	4095\(6,%r5\),4095\(9,%r10\)
.*:	b2 4d 00 69 [	 ]*cpya	%a6,%a9
.*:	19 69 [	 ]*cr	%r6,%r9
.*:	ba 69 5f ff [	 ]*cs	%r6,%r9,4095\(%r5\)
.*:	b2 30 00 00 [	 ]*csch
.*:	b2 50 00 69 [	 ]*csp	%r6,%r9
.*:	b2 57 00 69 [	 ]*cuse	%r6,%r9
.*:	b2 a7 00 69 [	 ]*cutfu	%r6,%r9
.*:	b2 a6 00 69 [	 ]*cuutf	%r6,%r9
.*:	4f 65 af ff [	 ]*cvb	%r6,4095\(%r5,%r10\)
.*:	4e 65 af ff [	 ]*cvd	%r6,4095\(%r5,%r10\)
.*:	b3 49 00 69 [	 ]*cxbr	%f6,%f9
.*:	b3 96 00 69 [	 ]*cxfbr	%f6,%r9
.*:	b3 b6 00 69 [	 ]*cxfr	%f6,%r9
.*:	b3 69 00 69 [	 ]*cxr	%f6,%f9
.*:	5d 65 af ff [	 ]*d	%r6,4095\(%r5,%r10\)
.*:	6d 65 af ff [	 ]*dd	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 1d [	 ]*ddb	%f6,4095\(%r5,%r10\)
.*:	b3 1d 00 69 [	 ]*ddbr	%f6,%f9
.*:	2d 69 [	 ]*ddr	%f6,%f9
.*:	7d 65 af ff [	 ]*de	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 0d [	 ]*deb	%f6,4095\(%r5,%r10\)
.*:	b3 0d 00 69 [	 ]*debr	%f6,%f9
.*:	3d 69 [	 ]*der	%f6,%f9
.*:	83 69 5f ff [	 ]*diag	%r6,%r9,4095\(%r5\)
.*:	b3 5b 9a 65 [	 ]*didbr	%f6,%f9,%f5,10
.*:	b3 53 9a 65 [	 ]*diebr	%f6,%f9,%f5,10
.*:	fd 58 5f ff af ff [	 ]*dp	4095\(6,%r5\),4095\(9,%r10\)
.*:	1d 69 [	 ]*dr	%r6,%r9
.*:	b3 4d 00 69 [	 ]*dxbr	%f6,%f9
.*:	b2 2d 00 69 [	 ]*dxr	%f6,%f9
.*:	b2 4f 00 69 [	 ]*ear	%r6,%a9
.*:	de ff 5f ff af ff [	 ]*ed	4095\(256,%r5\),4095\(%r10\)
.*:	df ff 5f ff af ff [	 ]*edmk	4095\(256,%r5\),4095\(%r10\)
.*:	b3 8c 00 69 [	 ]*efpc	%r6,%r9
.*:	b2 26 00 60 [	 ]*epar	%r6
.*:	b2 49 00 69 [	 ]*ereg	%r6,%r9
.*:	b2 27 00 60 [	 ]*esar	%r6
.*:	b2 4a 00 69 [	 ]*esta	%r6,%r9
.*:	44 65 af ff [	 ]*ex	%r6,4095\(%r5,%r10\)
.*:	b3 5f 50 69 [	 ]*fidbr	%f6,5,%f9
.*:	b3 7f 00 69 [	 ]*fidr	%f6,%f9
.*:	b3 57 50 69 [	 ]*fiebr	%f6,5,%f9
.*:	b3 77 00 69 [	 ]*fier	%f6,%f9
.*:	b3 47 50 69 [	 ]*fixbr	%f6,5,%f9
.*:	b3 67 00 69 [	 ]*fixr	%f6,%f9
.*:	24 69 [	 ]*hdr	%f6,%f9
.*:	34 69 [	 ]*her	%f6,%f9
.*:	b2 31 00 00 [	 ]*hsch
.*:	b2 24 00 60 [	 ]*iac	%r6
.*:	43 65 af ff [	 ]*ic	%r6,4095\(%r5,%r10\)
.*:	bf 6a 5f ff [	 ]*icm	%r6,10,4095\(%r5\)
.*:	b2 0b 00 00 [	 ]*ipk
.*:	b2 22 00 60 [	 ]*ipm	%r6
.*:	b2 21 00 69 [	 ]*ipte	%r6,%r9
.*:	b2 29 00 69 [	 ]*iske	%r6,%r9
.*:	b2 23 00 69 [	 ]*ivsk	%r6,%r9
.*:	a7 f4 00 00 [	 ]*j	268 <foo\+0x268>
.*:	a7 84 00 00 [	 ]*je	26c <foo\+0x26c>
.*:	a7 24 00 00 [	 ]*jh	270 <foo\+0x270>
.*:	a7 a4 00 00 [	 ]*jhe	274 <foo\+0x274>
.*:	a7 44 00 00 [	 ]*jl	278 <foo\+0x278>
.*:	a7 c4 00 00 [	 ]*jle	27c <foo\+0x27c>
.*:	a7 64 00 00 [	 ]*jlh	280 <foo\+0x280>
.*:	a7 44 00 00 [	 ]*jl	284 <foo\+0x284>
.*:	a7 74 00 00 [	 ]*jne	288 <foo\+0x288>
.*:	a7 d4 00 00 [	 ]*jnh	28c <foo\+0x28c>
.*:	a7 54 00 00 [	 ]*jnhe	290 <foo\+0x290>
.*:	a7 b4 00 00 [	 ]*jnl	294 <foo\+0x294>
.*:	a7 34 00 00 [	 ]*jnle	298 <foo\+0x298>
.*:	a7 94 00 00 [	 ]*jnlh	29c <foo\+0x29c>
.*:	a7 b4 00 00 [	 ]*jnl	2a0 <foo\+0x2a0>
.*:	a7 e4 00 00 [	 ]*jno	2a4 <foo\+0x2a4>
.*:	a7 d4 00 00 [	 ]*jnh	2a8 <foo\+0x2a8>
.*:	a7 74 00 00 [	 ]*jne	2ac <foo\+0x2ac>
.*:	a7 14 00 00 [	 ]*jo	2b0 <foo\+0x2b0>
.*:	a7 24 00 00 [	 ]*jh	2b4 <foo\+0x2b4>
.*:	a7 84 00 00 [	 ]*je	2b8 <foo\+0x2b8>
.*:	ed 65 af ff 00 18 [	 ]*kdb	%f6,4095\(%r5,%r10\)
.*:	b3 18 00 69 [	 ]*kdbr	%f6,%f9
.*:	ed 65 af ff 00 08 [	 ]*keb	%f6,4095\(%r5,%r10\)
.*:	b3 08 00 69 [	 ]*kebr	%f6,%f9
.*:	b3 48 00 69 [	 ]*kxbr	%f6,%f9
.*:	58 65 af ff [	 ]*l	%r6,4095\(%r5,%r10\)
.*:	41 65 af ff [	 ]*la	%r6,4095\(%r5,%r10\)
.*:	51 65 af ff [	 ]*lae	%r6,4095\(%r5,%r10\)
.*:	9a 69 5f ff [	 ]*lam	%a6,%a9,4095\(%r5\)
.*:	e5 00 5f ff af ff [	 ]*lasp	4095\(%r5\),4095\(%r10\)
.*:	b3 13 00 69 [	 ]*lcdbr	%f6,%f9
.*:	23 69 [	 ]*lcdr	%f6,%f9
.*:	b3 03 00 69 [	 ]*lcebr	%f6,%f9
.*:	33 69 [	 ]*lcer	%f6,%f9
.*:	13 69 [	 ]*lcr	%r6,%r9
.*:	b7 69 5f ff [	 ]*lctl	%c6,%c9,4095\(%r5\)
.*:	b3 43 00 69 [	 ]*lcxbr	%f6,%f9
.*:	b3 63 00 69 [	 ]*lcxr	%f6,%f9
.*:	68 65 af ff [	 ]*ld	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 24 [	 ]*lde	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 04 [	 ]*ldeb	%f6,4095\(%r5,%r10\)
.*:	b3 04 00 69 [	 ]*ldebr	%f6,%f9
.*:	b3 24 00 69 [	 ]*lder	%f6,%f9
.*:	28 69 [	 ]*ldr	%f6,%f9
.*:	b3 45 00 69 [	 ]*ldxbr	%f6,%f9
.*:	25 69 [	 ]*lrdr	%f6,%f9
.*:	78 65 af ff [	 ]*le	%f6,4095\(%r5,%r10\)
.*:	b3 44 00 69 [	 ]*ledbr	%f6,%f9
.*:	35 69 [	 ]*lrer	%f6,%f9
.*:	38 69 [	 ]*ler	%f6,%f9
.*:	b3 46 00 69 [	 ]*lexbr	%f6,%f9
.*:	b3 66 00 69 [	 ]*lexr	%f6,%f9
.*:	b2 9d 5f ff [	 ]*lfpc	4095\(%r5\)
.*:	48 65 af ff [	 ]*lh	%r6,4095\(%r5,%r10\)
.*:	a7 68 80 01 [	 ]*lhi	%r6,-32767
.*:	98 69 5f ff [	 ]*lm	%r6,%r9,4095\(%r5\)
.*:	b3 11 00 69 [	 ]*lndbr	%f6,%f9
.*:	21 69 [	 ]*lndr	%f6,%f9
.*:	b3 01 00 69 [	 ]*lnebr	%f6,%f9
.*:	31 69 [	 ]*lner	%f6,%f9
.*:	11 69 [	 ]*lnr	%r6,%r9
.*:	b3 41 00 69 [	 ]*lnxbr	%f6,%f9
.*:	b3 61 00 69 [	 ]*lnxr	%f6,%f9
.*:	b3 10 00 69 [	 ]*lpdbr	%f6,%f9
.*:	20 69 [	 ]*lpdr	%f6,%f9
.*:	b3 00 00 69 [	 ]*lpebr	%f6,%f9
.*:	30 69 [	 ]*lper	%f6,%f9
.*:	10 69 [	 ]*lpr	%r6,%r9
.*:	82 00 5f ff [	 ]*lpsw	4095\(%r5\)
.*:	b3 40 00 69 [	 ]*lpxbr	%f6,%f9
.*:	b3 60 00 69 [	 ]*lpxr	%f6,%f9
.*:	18 69 [	 ]*lr	%r6,%r9
.*:	b1 65 af ff [	 ]*lra	%r6,4095\(%r5,%r10\)
.*:	25 69 [	 ]*lrdr	%f6,%f9
.*:	35 69 [	 ]*lrer	%f6,%f9
.*:	b3 12 00 69 [	 ]*ltdbr	%f6,%f9
.*:	22 69 [	 ]*ltdr	%f6,%f9
.*:	b3 02 00 69 [	 ]*ltebr	%f6,%f9
.*:	32 69 [	 ]*lter	%f6,%f9
.*:	12 69 [	 ]*ltr	%r6,%r9
.*:	b3 42 00 69 [	 ]*ltxbr	%f6,%f9
.*:	b3 62 00 69 [	 ]*ltxr	%f6,%f9
.*:	b2 4b 00 69 [	 ]*lura	%r6,%r9
.*:	ed 65 af ff 00 25 [	 ]*lxd	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 05 [	 ]*lxdb	%f6,4095\(%r5,%r10\)
.*:	b3 05 00 69 [	 ]*lxdbr	%f6,%f9
.*:	b3 25 00 69 [	 ]*lxdr	%f6,%f9
.*:	ed 65 af ff 00 26 [	 ]*lxe	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 06 [	 ]*lxeb	%f6,4095\(%r5,%r10\)
.*:	b3 06 00 69 [	 ]*lxebr	%f6,%f9
.*:	b3 26 00 69 [	 ]*lxer	%f6,%f9
.*:	b3 65 00 69 [	 ]*lxr	%r6,%r9
.*:	b3 75 00 60 [	 ]*lzdr	%f6
.*:	b3 74 00 60 [	 ]*lzer	%f6
.*:	b3 76 00 60 [	 ]*lzxr	%f6
.*:	5c 65 af ff [	 ]*m	%r6,4095\(%r5,%r10\)
.*:	ed 95 af ff 60 1e [	 ]*madb	%f6,%f9,4095\(%r5,%r10\)
.*:	b3 1e 60 95 [	 ]*madbr	%f6,%f9,%f5
.*:	ed 95 af ff 60 0e [	 ]*maeb	%f6,%f9,4095\(%r5,%r10\)
.*:	b3 0e 60 95 [	 ]*maebr	%f6,%f9,%f5
.*:	af ff 5f ff [	 ]*mc	4095\(%r5\),255
.*:	6c 65 af ff [	 ]*md	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 1c [	 ]*mdb	%f6,4095\(%r5,%r10\)
.*:	b3 1c 00 69 [	 ]*mdbr	%f6,%f9
.*:	7c 65 af ff [	 ]*me	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 0c [	 ]*mdeb	%f6,4095\(%r5,%r10\)
.*:	b3 0c 00 69 [	 ]*mdebr	%f6,%f9
.*:	3c 69 [	 ]*mer	%f6,%f9
.*:	2c 69 [	 ]*mdr	%f6,%f9
.*:	7c 65 af ff [	 ]*me	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 37 [	 ]*mee	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 17 [	 ]*meeb	%f6,4095\(%r5,%r10\)
.*:	b3 17 00 69 [	 ]*meebr	%f6,%f9
.*:	b3 37 00 69 [	 ]*meer	%f6,%f9
.*:	3c 69 [	 ]*mer	%f6,%f9
.*:	4c 65 af ff [	 ]*mh	%r6,4095\(%r5,%r10\)
.*:	a7 6c 80 01 [	 ]*mhi	%r6,-32767
.*:	fc 58 5f ff af ff [	 ]*mp	4095\(6,%r5\),4095\(9,%r10\)
.*:	1c 69 [	 ]*mr	%r6,%r9
.*:	71 65 af ff [	 ]*ms	%r6,4095\(%r5,%r10\)
.*:	b2 32 5f ff [	 ]*msch	4095\(%r5\)
.*:	ed 95 af ff 60 1f [	 ]*msdb	%f6,%f9,4095\(%r5,%r10\)
.*:	b3 1f 60 95 [	 ]*msdbr	%f6,%f9,%f5
.*:	ed 95 af ff 60 0f [	 ]*mseb	%f6,%f9,4095\(%r5,%r10\)
.*:	b3 0f 60 95 [	 ]*msebr	%f6,%f9,%f5
.*:	b2 52 00 69 [	 ]*msr	%r6,%r9
.*:	b2 47 00 60 [	 ]*msta	%r6
.*:	d2 ff 5f ff af ff [	 ]*mvc	4095\(256,%r5\),4095\(%r10\)
.*:	e5 0f 5f ff af ff [	 ]*mvcdk	4095\(%r5\),4095\(%r10\)
.*:	e8 ff 5f ff af ff [	 ]*mvcin	4095\(256,%r5\),4095\(%r10\)
.*:	d9 69 5f ff af ff [	 ]*mvck	4095\(%r6,%r5\),4095\(%r10\),%r9
.*:	0e 69 [	 ]*mvcl	%r6,%r9
.*:	a8 69 5f ff [	 ]*mvcle	%r6,%r9,4095\(%r5\)
.*:	eb 69 5f ff 00 8e [	 ]*mvclu	%r6,%r9,4095\(%r5\)
.*:	da 69 5f ff af ff [	 ]*mvcp	4095\(%r6,%r5\),4095\(%r10\),%r9
.*:	db 69 5f ff af ff [	 ]*mvcs	4095\(%r6,%r5\),4095\(%r10\),%r9
.*:	e5 0e 5f ff af ff [	 ]*mvcsk	4095\(%r5\),4095\(%r10\)
.*:	92 ff 5f ff [	 ]*mvi	4095\(%r5\),255
.*:	d1 ff 5f ff af ff [	 ]*mvn	4095\(256,%r5\),4095\(%r10\)
.*:	f1 58 5f ff af ff [	 ]*mvo	4095\(6,%r5\),4095\(9,%r10\)
.*:	b2 54 00 69 [	 ]*mvpg	%r6,%r9
.*:	b2 55 00 69 [	 ]*mvst	%r6,%r9
.*:	d3 ff 5f ff af ff [	 ]*mvz	4095\(256,%r5\),4095\(%r10\)
.*:	b3 4c 00 69 [	 ]*mxbr	%f6,%f9
.*:	67 65 af ff [	 ]*mxd	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 07 [	 ]*mxdb	%f6,4095\(%r5,%r10\)
.*:	b3 07 00 69 [	 ]*mxdbr	%f6,%f9
.*:	27 69 [	 ]*mxdr	%f6,%f9
.*:	26 69 [	 ]*mxr	%f6,%f9
.*:	54 65 af ff [	 ]*n	%r6,4095\(%r5,%r10\)
.*:	d4 ff 5f ff af ff [	 ]*nc	4095\(256,%r5\),4095\(%r10\)
.*:	94 ff 5f ff [	 ]*ni	4095\(%r5\),255
.*:	47 05 af ff [	 ]*bc	0,4095\(%r5,%r10\)
.*:	07 09 [	 ]*bcr	0,%r9
.*:	14 69 [	 ]*nr	%r6,%r9
.*:	56 65 af ff [	 ]*o	%r6,4095\(%r5,%r10\)
.*:	d6 ff 5f ff af ff [	 ]*oc	4095\(256,%r5\),4095\(%r10\)
.*:	96 ff 5f ff [	 ]*oi	4095\(%r5\),255
.*:	16 69 [	 ]*or	%r6,%r9
.*:	f2 58 5f ff af ff [	 ]*pack	4095\(6,%r5\),4095\(9,%r10\)
.*:	b2 48 00 00 [	 ]*palb
.*:	b2 18 5f ff [	 ]*pc	4095\(%r5\)
.*:	b2 2e 00 69 [	 ]*pgin	%r6,%r9
.*:	b2 2f 00 69 [	 ]*pgout	%r6,%r9
.*:	e9 1f 5f ff af ff [	 ]*pka	4095\(%r5\),4095\(32,%r10\)
.*:	e1 ff 5f ff af ff [	 ]*pku	4095\(256,%r5\),4095\(%r10\)
.*:	ee 69 5f ff af ff [	 ]*plo	%r6,4095\(%r5\),%r9,4095\(%r10\)
.*:	01 01 [	 ]*pr
.*:	b2 28 00 69 [	 ]*pt	%r6,%r9
.*:	b2 0d 00 00 [	 ]*ptlb
.*:	b2 3b 00 00 [	 ]*rchp
.*:	b2 77 5f ff [	 ]*rp	4095\(%r5\)
.*:	b2 2a 00 69 [	 ]*rrbe	%r6,%r9
.*:	b2 38 00 00 [	 ]*rsch
.*:	5b 65 af ff [	 ]*s	%r6,4095\(%r5,%r10\)
.*:	b2 19 5f ff [	 ]*sac	4095\(%r5\)
.*:	b2 79 5f ff [	 ]*sacf	4095\(%r5\)
.*:	b2 37 00 00 [	 ]*sal
.*:	b2 4e 00 69 [	 ]*sar	%a6,%r9
.*:	b2 3c 00 00 [	 ]*schm
.*:	b2 04 5f ff [	 ]*sck	4095\(%r5\)
.*:	b2 06 5f ff [	 ]*sckc	4095\(%r5\)
.*:	01 07 [	 ]*sckpf
.*:	6b 65 af ff [	 ]*sd	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 1b [	 ]*sdb	%f6,4095\(%r5,%r10\)
.*:	b3 1b 00 69 [	 ]*sdbr	%f6,%f9
.*:	2b 69 [	 ]*sdr	%f6,%f9
.*:	7b 65 af ff [	 ]*se	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 0b [	 ]*seb	%f6,4095\(%r5,%r10\)
.*:	b3 0b 00 69 [	 ]*sebr	%f6,%f9
.*:	3b 69 [	 ]*ser	%f6,%f9
.*:	b3 84 00 69 [	 ]*sfpc	%r6,%r9
.*:	4b 65 af ff [	 ]*sh	%r6,4095\(%r5,%r10\)
.*:	b2 14 5f ff [	 ]*sie	4095\(%r5\)
.*:	b2 74 5f ff [	 ]*siga	4095\(%r5\)
.*:	ae 69 5f ff [	 ]*sigp	%r6,%r9,4095\(%r5\)
.*:	5f 65 af ff [	 ]*sl	%r6,4095\(%r5,%r10\)
.*:	8b 60 5f ff [	 ]*sla	%r6,4095\(%r5\)
.*:	8f 60 5f ff [	 ]*slda	%r6,4095\(%r5\)
.*:	8d 60 5f ff [	 ]*sldl	%r6,4095\(%r5\)
.*:	89 60 5f ff [	 ]*sll	%r6,4095\(%r5\)
.*:	1f 69 [	 ]*slr	%r6,%r9
.*:	fb 58 5f ff af ff [	 ]*sp	4095\(6,%r5\),4095\(9,%r10\)
.*:	b2 0a 5f ff [	 ]*spka	4095\(%r5\)
.*:	04 60 [	 ]*spm	%r6
.*:	b2 08 5f ff [	 ]*spt	4095\(%r5\)
.*:	b2 10 5f ff [	 ]*spx	4095\(%r5\)
.*:	ed 65 af ff 00 15 [	 ]*sqdb	%f6,4095\(%r5,%r10\)
.*:	b3 15 00 69 [	 ]*sqdbr	%f6,%f9
.*:	b2 44 00 69 [	 ]*sqdr	%f6,%f9
.*:	ed 65 af ff 00 34 [	 ]*sqe	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 14 [	 ]*sqeb	%f6,4095\(%r5,%r10\)
.*:	b3 14 00 69 [	 ]*sqebr	%f6,%f9
.*:	b2 45 00 69 [	 ]*sqer	%f6,%f9
.*:	b3 16 00 69 [	 ]*sqxbr	%f6,%f9
.*:	b3 36 00 69 [	 ]*sqxr	%f6,%f9
.*:	1b 69 [	 ]*sr	%r6,%r9
.*:	8a 60 5f ff [	 ]*sra	%r6,4095\(%r5\)
.*:	8e 60 5f ff [	 ]*srda	%r6,4095\(%r5\)
.*:	8c 60 5f ff [	 ]*srdl	%r6,4095\(%r5\)
.*:	88 60 5f ff [	 ]*srl	%r6,4095\(%r5\)
.*:	b2 99 5f ff [	 ]*srnm	4095\(%r5\)
.*:	f0 fa 5f ff af ff [	 ]*srp	4095\(16,%r5\),4095\(%r10\),10
.*:	b2 5e 00 69 [	 ]*srst	%r6,%r9
.*:	b2 25 00 60 [	 ]*ssar	%r6
.*:	b2 33 5f ff [	 ]*ssch	4095\(%r5\)
.*:	b2 2b 00 69 [	 ]*sske	%r6,%r9
.*:	80 00 5f ff [	 ]*ssm	4095\(%r5\)
.*:	50 65 af ff [	 ]*st	%r6,4095\(%r5,%r10\)
.*:	9b 69 5f ff [	 ]*stam	%a6,%a9,4095\(%r5\)
.*:	b2 12 5f ff [	 ]*stap	4095\(%r5\)
.*:	42 65 af ff [	 ]*stc	%r6,4095\(%r5,%r10\)
.*:	b2 05 5f ff [	 ]*stck	4095\(%r5\)
.*:	b2 07 5f ff [	 ]*stckc	4095\(%r5\)
.*:	b2 78 5f ff [	 ]*stcke	4095\(%r5\)
.*:	be 6a 5f ff [	 ]*stcm	%r6,10,4095\(%r5\)
.*:	b2 3a 5f ff [	 ]*stcps	4095\(%r5\)
.*:	b2 39 5f ff [	 ]*stcrw	4095\(%r5\)
.*:	b6 69 5f ff [	 ]*stctl	%c6,%c9,4095\(%r5\)
.*:	60 65 af ff [	 ]*std	%f6,4095\(%r5,%r10\)
.*:	70 65 af ff [	 ]*ste	%f6,4095\(%r5,%r10\)
.*:	b2 9c 5f ff [	 ]*stfpc	4095\(%r5\)
.*:	40 65 af ff [	 ]*sth	%r6,4095\(%r5,%r10\)
.*:	b2 02 5f ff [	 ]*stidp	4095\(%r5\)
.*:	90 69 5f ff [	 ]*stm	%r6,%r9,4095\(%r5\)
.*:	ac ff 5f ff [	 ]*stnsm	4095\(%r5\),255
.*:	ad ff 5f ff [	 ]*stosm	4095\(%r5\),255
.*:	b2 09 5f ff [	 ]*stpt	4095\(%r5\)
.*:	b2 11 5f ff [	 ]*stpx	4095\(%r5\)
.*:	b2 34 5f ff [	 ]*stsch	4095\(%r5\)
.*:	b2 7d 5f ff [	 ]*stsi	4095\(%r5\)
.*:	b2 46 00 69 [	 ]*stura	%r6,%r9
.*:	7f 65 af ff [	 ]*su	%f6,4095\(%r5,%r10\)
.*:	3f 69 [	 ]*sur	%f6,%f9
.*:	0a ff [	 ]*svc	255
.*:	6f 65 af ff [	 ]*sw	%f6,4095\(%r5,%r10\)
.*:	2f 69 [	 ]*swr	%f6,%f9
.*:	b3 4b 00 69 [	 ]*sxbr	%f6,%f9
.*:	37 69 [	 ]*sxr	%f6,%f9
.*:	b2 4c 00 69 [	 ]*tar	%a6,%r9
.*:	b2 2c 00 06 [	 ]*tb	%r6
.*:	b3 51 50 69 [	 ]*tbdr	%f6,5,%f9
.*:	b3 50 50 69 [	 ]*tbedr	%f6,5,%f9
.*:	ed 65 af ff 00 11 [	 ]*tcdb	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 10 [	 ]*tceb	%f6,4095\(%r5,%r10\)
.*:	ed 65 af ff 00 12 [	 ]*tcxb	%f6,4095\(%r5,%r10\)
.*:	b3 58 00 69 [	 ]*thder	%r6,%r9
.*:	b3 59 00 69 [	 ]*thdr	%r6,%r9
.*:	91 ff 5f ff [	 ]*tm	4095\(%r5\),255
.*:	a7 60 ff ff [	 ]*tmh	%r6,65535
.*:	a7 61 ff ff [	 ]*tml	%r6,65535
.*:	a7 60 ff ff [	 ]*tmh	%r6,65535
.*:	a7 61 ff ff [	 ]*tml	%r6,65535
.*:	eb 50 5f ff 00 c0 [	 ]*tp	4095\(6,%r5\)
.*:	b2 36 5f ff [	 ]*tpi	4095\(%r5\)
.*:	e5 01 5f ff af ff [	 ]*tprot	4095\(%r5\),4095\(%r10\)
.*:	dc ff 5f ff af ff [	 ]*tr	4095\(256,%r5\),4095\(%r10\)
.*:	99 69 5f ff [	 ]*trace	%r6,%r9,4095\(%r5\)
.*:	01 ff [	 ]*trap2
.*:	b2 ff 5f ff [	 ]*trap4	4095\(%r5\)
.*:	b2 a5 00 69 [	 ]*tre	%r6,%r9
.*:	b9 93 00 69 [	 ]*troo	%r6,%r9,0
.*:	b9 92 00 69 [	 ]*trot	%r6,%r9,0
.*:	dd ff 5f ff af ff [	 ]*trt	4095\(256,%r5\),4095\(%r10\)
.*:	b9 91 00 69 [	 ]*trto	%r6,%r9,0
.*:	b9 90 00 69 [	 ]*trtt	%r6,%r9,0
.*:	93 00 5f ff [	 ]*ts	4095\(%r5\)
.*:	b2 35 5f ff [	 ]*tsch	4095\(%r5\)
.*:	f3 58 5f ff af ff [	 ]*unpk	4095\(6,%r5\),4095\(9,%r10\)
.*:	ea ff 5f ff af ff [	 ]*unpka	4095\(256,%r5\),4095\(%r10\)
.*:	e2 ff 5f ff af ff [	 ]*unpku	4095\(256,%r5\),4095\(%r10\)
.*:	01 02 [	 ]*upt
.*:	57 65 af ff [	 ]*x	%r6,4095\(%r5,%r10\)
.*:	d7 ff 5f ff af ff [	 ]*xc	4095\(256,%r5\),4095\(%r10\)
.*:	97 ff 5f ff [	 ]*xi	4095\(%r5\),255
.*:	17 69 [	 ]*xr	%r6,%r9
.*:	b2 76 00 00 [	 ]*xsch
.*:	f8 58 5f ff af ff [	 ]*zap	4095\(6,%r5\),4095\(9,%r10\)
