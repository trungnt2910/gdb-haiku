#objdump: -dr --prefix-addresses --show-raw-insn -M gpr-names=numeric,cp0-names=r3000
#name: MIPS CP0 register disassembly (r3000)
#as: -32 -march=r3000
#source: cp0-names.s

# Check objdump's handling of -M cp0-names=foo options.

.*: +file format .*mips.*

Disassembly of section \.text:
[0-9a-f]+ <[^>]*> 40800000 	mtc0	\$0,c0_index
[0-9a-f]+ <[^>]*> 40800800 	mtc0	\$0,c0_random
[0-9a-f]+ <[^>]*> 40801000 	mtc0	\$0,c0_entrylo
[0-9a-f]+ <[^>]*> 40801800 	mtc0	\$0,\$3
[0-9a-f]+ <[^>]*> 40802000 	mtc0	\$0,c0_context
[0-9a-f]+ <[^>]*> 40802800 	mtc0	\$0,\$5
[0-9a-f]+ <[^>]*> 40803000 	mtc0	\$0,\$6
[0-9a-f]+ <[^>]*> 40803800 	mtc0	\$0,\$7
[0-9a-f]+ <[^>]*> 40804000 	mtc0	\$0,c0_badvaddr
[0-9a-f]+ <[^>]*> 40804800 	mtc0	\$0,\$9
[0-9a-f]+ <[^>]*> 40805000 	mtc0	\$0,c0_entryhi
[0-9a-f]+ <[^>]*> 40805800 	mtc0	\$0,\$11
[0-9a-f]+ <[^>]*> 40806000 	mtc0	\$0,c0_sr
[0-9a-f]+ <[^>]*> 40806800 	mtc0	\$0,c0_cause
[0-9a-f]+ <[^>]*> 40807000 	mtc0	\$0,c0_epc
[0-9a-f]+ <[^>]*> 40807800 	mtc0	\$0,c0_prid
[0-9a-f]+ <[^>]*> 40808000 	mtc0	\$0,\$16
[0-9a-f]+ <[^>]*> 40808800 	mtc0	\$0,\$17
[0-9a-f]+ <[^>]*> 40809000 	mtc0	\$0,\$18
[0-9a-f]+ <[^>]*> 40809800 	mtc0	\$0,\$19
[0-9a-f]+ <[^>]*> 4080a000 	mtc0	\$0,\$20
[0-9a-f]+ <[^>]*> 4080a800 	mtc0	\$0,\$21
[0-9a-f]+ <[^>]*> 4080b000 	mtc0	\$0,\$22
[0-9a-f]+ <[^>]*> 4080b800 	mtc0	\$0,\$23
[0-9a-f]+ <[^>]*> 4080c000 	mtc0	\$0,\$24
[0-9a-f]+ <[^>]*> 4080c800 	mtc0	\$0,\$25
[0-9a-f]+ <[^>]*> 4080d000 	mtc0	\$0,\$26
[0-9a-f]+ <[^>]*> 4080d800 	mtc0	\$0,\$27
[0-9a-f]+ <[^>]*> 4080e000 	mtc0	\$0,\$28
[0-9a-f]+ <[^>]*> 4080e800 	mtc0	\$0,\$29
[0-9a-f]+ <[^>]*> 4080f000 	mtc0	\$0,\$30
[0-9a-f]+ <[^>]*> 4080f800 	mtc0	\$0,\$31
	\.\.\.
